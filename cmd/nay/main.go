package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/victortrac/nay/internal/aur"
	"github.com/victortrac/nay/internal/cache"
	"github.com/victortrac/nay/internal/config"
	"github.com/victortrac/nay/internal/llm"
	"github.com/victortrac/nay/internal/scanner"
	"github.com/victortrac/nay/internal/ui"
	"github.com/victortrac/nay/internal/wrapper"
)

var version = "0.1.0"

// aurRPC abstracts aur.RPCClient for testing.
type aurRPC interface {
	ResolveAURDeps(ctx context.Context, roots []string, isRepoPkg func(string) bool) ([]aur.PackageInfo, error)
}

// repoSyncer abstracts aur.GitFetcher for testing.
type repoSyncer interface {
	SyncRepo(ctx context.Context, cacheDir, pkgBase, prevCommitSHA string) (*aur.RepoSnapshot, error)
}

type app struct {
	in         io.Reader
	out        io.Writer
	errOut     io.Writer
	errMu      sync.Mutex
	cfgPath    string
	reposDir   string
	cachePath  string
	rpcClient  aurRPC
	gitFetcher repoSyncer
	llmFactory func(llm.ProviderConfig) (llm.Client, error)
	runner     wrapper.CommandRunner
}

func (a *app) logErrf(format string, args ...any) {
	a.errMu.Lock()
	defer a.errMu.Unlock()
	fmt.Fprintf(a.errOut, format, args...)
}

func defaultApp() *app {
	return &app{
		in:         os.Stdin,
		out:        os.Stdout,
		errOut:     os.Stderr,
		cfgPath:    config.ConfigPath(),
		reposDir:   config.ReposDir(),
		cachePath:  config.AuditCachePath(),
		rpcClient:  aur.NewRPCClient(),
		gitFetcher: aur.NewGitFetcher(),
		llmFactory: llm.NewClient,
		runner:     wrapper.OSCommandRunner{},
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	code := defaultApp().run(ctx, os.Args[1:])
	os.Exit(code)
}

func (a *app) run(ctx context.Context, args []string) int {
	cmd, err := wrapper.ParseArgs(args)
	if err != nil {
		fmt.Fprintf(a.errOut, "nay: %v\n", err)
		return 2
	}

	switch cmd.Mode {
	case wrapper.ModeVersion:
		fmt.Fprintf(a.out, "nay %s\n", version)
		return 0
	case wrapper.ModeHelp:
		a.printHelp()
		return 0
	case wrapper.ModeConfigInit:
		return a.runConfigInit(cmd.ConfigForce)
	}

	cfg, err := config.Load(a.cfgPath)
	if err != nil {
		fmt.Fprintf(a.errOut, "nay: failed to load config %s: %v\n", a.cfgPath, err)
		return 1
	}
	if cmd.Backend != "" {
		cfg.Backend = cmd.Backend
	}
	if cmd.Model != "" {
		cfg.LLM.Model = cmd.Model
	}

	backend := wrapper.NewBackend(cfg.Backend, a.runner)

	switch cmd.Mode {
	case wrapper.ModeDoctor:
		return a.runDoctor(ctx, cfg)
	case wrapper.ModePassthrough:
		code, err := backend.Passthrough(ctx, cmd.BackendArgs)
		if err != nil {
			fmt.Fprintf(a.errOut, "nay: failed to run %s: %v\n", backend.Name, err)
			return 1
		}
		return code
	case wrapper.ModeAudit:
		return a.runAuditOnly(ctx, cfg, backend, cmd)
	case wrapper.ModeInstall:
		return a.runInstall(ctx, cfg, backend, cmd)
	case wrapper.ModeUpgrade:
		return a.runUpgrade(ctx, cfg, backend, cmd)
	default:
		fmt.Fprintf(a.errOut, "nay: unsupported mode %v\n", cmd.Mode)
		return 1
	}
}

func (a *app) runConfigInit(force bool) int {
	if err := config.WriteDefault(a.cfgPath, force); err != nil {
		fmt.Fprintf(a.errOut, "nay: %v\n", err)
		return 1
	}
	fmt.Fprintf(a.out, "Wrote default config to %s\n", a.cfgPath)
	return 0
}

func (a *app) runDoctor(ctx context.Context, cfg *config.Config) int {
	allOK := true
	check := func(name string, ok bool, detail string) {
		status := "[ok]"
		if !ok {
			status = "[FAIL]"
			allOK = false
		}
		fmt.Fprintf(a.out, "  %-6s %-14s %s\n", status, name, detail)
	}

	fmt.Fprintln(a.out, ":: Checking nay environment...")

	if _, err := os.Stat(a.cfgPath); err == nil {
		check("config", true, a.cfgPath)
	} else {
		check("config", true, fmt.Sprintf("%s (not found; using defaults — run `nay config init`)", a.cfgPath))
	}

	for _, bin := range []string{cfg.Backend, "pacman", "git"} {
		path, err := exec.LookPath(bin)
		if err != nil {
			check(bin, false, fmt.Sprintf("not found in PATH (%v)", err))
		} else {
			check(bin, true, path)
		}
	}

	if err := os.MkdirAll(a.reposDir, 0o755); err != nil {
		check("cache", false, fmt.Sprintf("cannot create %s: %v", a.reposDir, err))
	} else {
		check("cache", true, a.reposDir)
	}

	client, err := a.newLLMClient(cfg)
	if err != nil {
		check("llm", false, fmt.Sprintf("invalid LLM config (%s/%s): %v", cfg.LLM.Provider, cfg.LLM.Model, err))
	} else {
		pingCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := client.Ping(pingCtx); err != nil {
			check("llm", false, fmt.Sprintf("%s (%s): %v", cfg.LLM.Provider, cfg.LLM.Model, err))
		} else {
			check("llm", true, fmt.Sprintf("%s (%s) reachable", cfg.LLM.Provider, cfg.LLM.Model))
		}
	}

	if !allOK {
		return 1
	}
	return 0
}

func (a *app) runAuditOnly(ctx context.Context, cfg *config.Config, backend *wrapper.Backend, cmd *wrapper.Command) int {
	isRepo := func(name string) bool { return backend.IsRepoPackage(ctx, name) }
	roots := make([]string, 0, len(cmd.Targets))
	for _, t := range cmd.Targets {
		pkg, _ := wrapper.StripAURPrefix(t)
		roots = append(roots, pkg)
	}
	pkgs, err := a.rpcClient.ResolveAURDeps(ctx, roots, isRepo)
	if err != nil {
		fmt.Fprintf(a.errOut, "nay: failed to resolve AUR packages: %v\n", err)
		return 1
	}
	if len(pkgs) == 0 {
		fmt.Fprintf(a.errOut, "nay: no AUR packages found for %s\n", strings.Join(cmd.Targets, ", "))
		return 1
	}

	items, err := a.auditPackages(ctx, cfg, pkgs, cmd.ForceAudit)
	if err != nil {
		fmt.Fprintf(a.errOut, "nay: %v\n", err)
		return 1
	}

	u := ui.New(a.in, a.out)
	u.RenderTable(items, nil)
	u.RenderFindings(items)

	for _, it := range items {
		if it.Verdict == ui.VerdictDangerous || it.Error != "" {
			return 1
		}
	}
	return 0
}

func (a *app) runInstall(ctx context.Context, cfg *config.Config, backend *wrapper.Backend, cmd *wrapper.Command) int {
	isRepo := func(name string) bool { return backend.IsRepoPackage(ctx, name) }

	var aurTargets []string
	for _, t := range cmd.Targets {
		pkg, explicitAUR := wrapper.StripAURPrefix(t)
		if explicitAUR || !isRepo(pkg) {
			aurTargets = append(aurTargets, pkg)
		}
	}

	if len(aurTargets) == 0 {
		code, err := backend.Passthrough(ctx, cmd.BackendArgs)
		if err != nil {
			fmt.Fprintf(a.errOut, "nay: failed to run %s: %v\n", backend.Name, err)
			return 1
		}
		return code
	}

	fmt.Fprintf(a.out, ":: Resolving AUR dependencies for %s...\n", strings.Join(aurTargets, ", "))
	pkgs, err := a.rpcClient.ResolveAURDeps(ctx, aurTargets, isRepo)
	if err != nil {
		fmt.Fprintf(a.errOut, "nay: failed to resolve AUR packages: %v\n", err)
		return 1
	}
	if len(pkgs) == 0 {
		code, err := backend.Passthrough(ctx, cmd.BackendArgs)
		if err != nil {
			fmt.Fprintf(a.errOut, "nay: failed to run %s: %v\n", backend.Name, err)
			return 1
		}
		return code
	}

	return a.auditAndInstall(ctx, cfg, backend, cmd, pkgs)
}

func (a *app) runUpgrade(ctx context.Context, cfg *config.Config, backend *wrapper.Backend, cmd *wrapper.Command) int {
	fmt.Fprintln(a.out, ":: Checking AUR upgrades...")
	pending, err := backend.PendingAURUpgrades(ctx)
	if err != nil {
		fmt.Fprintf(a.errOut, "nay: %v\n", err)
		return 1
	}

	isRepo := func(name string) bool { return backend.IsRepoPackage(ctx, name) }
	seen := make(map[string]bool, len(pending)+len(cmd.Targets))
	var roots []string
	for _, p := range pending {
		pkg, _ := wrapper.StripAURPrefix(p)
		if !seen[pkg] {
			seen[pkg] = true
			roots = append(roots, pkg)
		}
	}
	for _, t := range cmd.Targets {
		pkg, explicitAUR := wrapper.StripAURPrefix(t)
		if !seen[pkg] && (explicitAUR || !isRepo(pkg)) {
			seen[pkg] = true
			roots = append(roots, pkg)
		}
	}

	if len(roots) == 0 {
		code, err := backend.Passthrough(ctx, cmd.BackendArgs)
		if err != nil {
			fmt.Fprintf(a.errOut, "nay: failed to run %s: %v\n", backend.Name, err)
			return 1
		}
		return code
	}

	fmt.Fprintf(a.out, ":: Found %d pending AUR upgrade(s); resolving dependencies...\n", len(roots))
	pkgs, err := a.rpcClient.ResolveAURDeps(ctx, roots, isRepo)
	if err != nil {
		fmt.Fprintf(a.errOut, "nay: failed to resolve AUR packages: %v\n", err)
		return 1
	}
	if len(pkgs) == 0 {
		code, err := backend.Passthrough(ctx, cmd.BackendArgs)
		if err != nil {
			fmt.Fprintf(a.errOut, "nay: failed to run %s: %v\n", backend.Name, err)
			return 1
		}
		return code
	}

	return a.auditAndInstall(ctx, cfg, backend, cmd, pkgs)
}

func (a *app) auditAndInstall(ctx context.Context, cfg *config.Config, backend *wrapper.Backend, cmd *wrapper.Command, pkgs []aur.PackageInfo) int {
	items, err := a.auditPackages(ctx, cfg, pkgs, cmd.ForceAudit)
	if err != nil {
		fmt.Fprintf(a.errOut, "nay: %v\n", err)
		return 1
	}

	u := ui.New(a.in, a.out)

	if canAutoApprove(cfg.AutoApproveSafe, items) {
		u.RenderTable(items, nil)
		u.RenderFindings(items)
		fmt.Fprintln(a.out, ":: All packages SAFE with no static warnings — auto-approving.")
		code, err := backend.InstallApproved(ctx, cmd.BackendArgs, nil)
		if err != nil {
			fmt.Fprintf(a.errOut, "nay: failed to run %s: %v\n", backend.Name, err)
			return 1
		}
		return code
	}

	dec, err := u.Prompt(items)
	if err != nil {
		fmt.Fprintf(a.errOut, "nay: prompt error: %v\n", err)
		return 1
	}
	if !dec.Proceed {
		fmt.Fprintln(a.out, ":: Aborted.")
		return 1
	}

	code, err := backend.InstallApproved(ctx, cmd.BackendArgs, dec.Skipped)
	if err != nil {
		fmt.Fprintf(a.errOut, "nay: failed to run %s: %v\n", backend.Name, err)
		return 1
	}
	return code
}

func (a *app) newLLMClient(cfg *config.Config) (llm.Client, error) {
	return a.llmFactory(llm.ProviderConfig{
		Provider:       cfg.LLM.Provider,
		Model:          cfg.LLM.Model,
		BaseURL:        cfg.LLM.BaseURL,
		APIKey:         cfg.ResolveAPIKey(),
		TimeoutSeconds: cfg.LLM.TimeoutSeconds,
	})
}

func (a *app) auditPackages(ctx context.Context, cfg *config.Config, pkgs []aur.PackageInfo, forceAudit bool) ([]ui.AuditItem, error) {
	client, err := a.newLLMClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize LLM client: %w", err)
	}

	store, err := cache.Open(a.cachePath)
	if err != nil {
		fmt.Fprintf(a.errOut, "nay: warning: failed to open audit cache %s: %v\n", a.cachePath, err)
		store = nil
	}

	fmt.Fprintf(a.out, ":: Auditing %d AUR package(s) with %s...\n", len(pkgs), cfg.LLM.Model)

	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	if concurrency > len(pkgs) {
		concurrency = len(pkgs)
	}

	results := make([]ui.AuditItem, len(pkgs))
	jobs := make(chan int, len(pkgs))
	for i := range pkgs {
		jobs <- i
	}
	close(jobs)

	// Guard concurrent git syncs for split packages sharing the same PackageBase.
	var repoLocks sync.Map
	lockForBase := func(base string) *sync.Mutex {
		mu, _ := repoLocks.LoadOrStore(base, &sync.Mutex{})
		return mu.(*sync.Mutex)
	}

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				results[idx] = a.auditOne(ctx, cfg, client, store, pkgs[idx], forceAudit, lockForBase)
			}
		}()
	}
	wg.Wait()

	if errors.Is(ctx.Err(), context.Canceled) {
		return nil, ctx.Err()
	}
	return results, nil
}

func (a *app) auditOne(
	ctx context.Context,
	cfg *config.Config,
	client llm.Client,
	store *cache.Store,
	pkg aur.PackageInfo,
	forceAudit bool,
	lockForBase func(string) *sync.Mutex,
) ui.AuditItem {
	pkgBase := pkg.PackageBase
	if pkgBase == "" {
		pkgBase = pkg.Name
	}

	item := ui.AuditItem{
		PackageName: pkg.Name,
		PackageBase: pkgBase,
		Version:     pkg.Version,
	}

	var prevCommit string
	if store != nil {
		prevCommit = store.LastCommit(pkg.Name)
	}

	mu := lockForBase(pkgBase)
	mu.Lock()
	snap, err := a.gitFetcher.SyncRepo(ctx, a.reposDir, pkgBase, prevCommit)
	mu.Unlock()
	if err != nil {
		item.Verdict = ui.VerdictDangerous
		item.Error = fmt.Sprintf("git sync failed: %v", err)
		return item
	}

	item.CommitSHA = snap.CommitSHA
	item.Diff = snap.Diff
	item.Files = make([]ui.RepoFile, 0, len(snap.Files))
	scanFiles := make([]scanner.File, 0, len(snap.Files))
	llmFiles := make([]llm.RepoFile, 0, len(snap.Files))
	for _, f := range snap.Files {
		item.Files = append(item.Files, ui.RepoFile{
			Path:      f.Path,
			Content:   f.Content,
			Truncated: f.Truncated,
		})
		scanFiles = append(scanFiles, scanner.File{
			Path:    f.Path,
			Content: f.Content,
		})
		llmFiles = append(llmFiles, llm.RepoFile{
			Path:      f.Path,
			Content:   f.Content,
			Truncated: f.Truncated,
		})
	}

	flags := scanner.Scan(scanner.Input{
		PackageName:    pkg.Name,
		NumVotes:       pkg.NumVotes,
		Popularity:     pkg.Popularity,
		Maintainer:     pkg.Maintainer,
		FirstSubmitted: pkg.FirstSubmitted,
		LastModified:   pkg.LastModified,
		OutOfDate:      pkg.OutOfDate,
		Files:          scanFiles,
	})

	flagStrings := make([]string, 0, len(flags))
	item.StaticFlags = make([]ui.StaticFinding, 0, len(flags))
	for _, fl := range flags {
		flagStrings = append(flagStrings, fl.String())
		item.StaticFlags = append(item.StaticFlags, ui.StaticFinding{
			Severity: string(fl.Severity),
			Code:     fl.Code,
			File:     fl.File,
			Message:  fl.Message,
		})
	}

	if !forceAudit && store != nil {
		if entry, ok := store.Get(pkg.Name, snap.CommitSHA, cfg.LLM.Model); ok {
			item.Verdict = ui.Verdict(entry.Verdict)
			item.Cached = true
			item.Summary = entry.Summary
			item.Findings = entry.Findings
			item.Reasoning = entry.Reasoning
			return item
		}
	}

	req := llm.AuditRequest{
		PackageName:    pkg.Name,
		PackageBase:    pkgBase,
		Version:        pkg.Version,
		Description:    pkg.Description,
		UpstreamURL:    pkg.URL,
		Maintainer:     pkg.Maintainer,
		NumVotes:       pkg.NumVotes,
		Popularity:     pkg.Popularity,
		FirstSubmitted: pkg.FirstSubmitted,
		LastModified:   pkg.LastModified,
		OutOfDate:      pkg.OutOfDate,
		CommitSHA:      snap.CommitSHA,
		Diff:           snap.Diff,
		Files:          llmFiles,
		StaticFlags:    flagStrings,
	}

	resp, err := client.Audit(ctx, req)
	if err != nil {
		item.Verdict = ui.VerdictDangerous
		item.Error = fmt.Sprintf("LLM audit failed: %v", err)
		return item
	}

	item.Verdict = ui.Verdict(resp.Verdict)
	item.Summary = resp.Summary
	item.Findings = resp.Findings
	item.Reasoning = resp.Reasoning

	if store != nil {
		if putErr := store.Put(cache.Entry{
			Package:     pkg.Name,
			CommitSHA:   snap.CommitSHA,
			Model:       cfg.LLM.Model,
			Verdict:     string(resp.Verdict),
			Summary:     resp.Summary,
			Findings:    resp.Findings,
			Reasoning:   resp.Reasoning,
			StaticFlags: flagStrings,
			AuditedAt:   time.Now().UTC(),
		}); putErr != nil {
			a.logErrf("nay: warning: failed to save cache entry for %s: %v\n", pkg.Name, putErr)
		}
	}

	return item
}

// canAutoApprove returns true only when auto_approve_safe is enabled and every
// package is SAFE with no errors and no HIGH or WARN static flags.
func canAutoApprove(autoApproveSafe bool, items []ui.AuditItem) bool {
	if !autoApproveSafe || len(items) == 0 {
		return false
	}
	for _, it := range items {
		if it.Verdict != ui.VerdictSafe || it.Error != "" {
			return false
		}
		for _, fl := range it.StaticFlags {
			if fl.Severity == string(scanner.SeverityHigh) || fl.Severity == string(scanner.SeverityWarn) {
				return false
			}
		}
	}
	return true
}

func (a *app) printHelp() {
	fmt.Fprintf(a.out, `nay %s — Say nay to malicious AUR packages.

Drop-in wrapper around yay/paru that audits AUR packages with deterministic
static security checks and an LLM before anything is built or installed.

USAGE:
  nay [yay/paru flags...]          Drop-in yay/paru wrapper (bare nay runs -Syu)
  nay -S <pkg...>                  Audit AUR targets + deps, then install
  nay -Syu                         Audit pending AUR upgrades, then upgrade
  nay audit <pkg...>               Dry-run audit AUR packages without installing
  nay config init [--force]        Write default config to ~/.config/nay/config.toml
  nay doctor                       Check backend, pacman, git, cache, and LLM connectivity
  nay version                      Print nay version
  nay help                         Show this help message

OVERRIDE FLAGS:
  --force-audit                    Bypass commit-SHA audit cache and re-audit fresh
  --no-audit                       Skip auditing and pass directly through to yay/paru
  --model <name>                   Override configured LLM model for this run
  --backend <yay|paru>             Override configured AUR helper backend for this run
`, version)
}
