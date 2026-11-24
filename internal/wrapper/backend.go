package wrapper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// CommandRunner abstracts process execution for unit testing.
type CommandRunner interface {
	RunInteractive(ctx context.Context, name string, args []string) (exitCode int, err error)
	RunCapture(ctx context.Context, name string, args []string) (stdout []byte, exitCode int, err error)
}

// OSCommandRunner executes commands using os/exec.
type OSCommandRunner struct{}

func (OSCommandRunner) RunInteractive(ctx context.Context, name string, args []string) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return 1, err
}

func (OSCommandRunner) RunCapture(ctx context.Context, name string, args []string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err == nil {
		return out, 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return out, exitErr.ExitCode(), exitErr
	}
	return out, 1, err
}

// Backend wraps yay or paru (and pacman for repo checks).
type Backend struct {
	Name   string // "yay" or "paru"
	Pacman string // defaults to "pacman"
	Runner CommandRunner

	syncOnce  sync.Once
	syncRepos map[string]bool

	repoMu    sync.RWMutex
	repoCache map[string]bool
}

// NewBackend creates a Backend for the given AUR helper ("yay" or "paru").
func NewBackend(name string, runner CommandRunner) *Backend {
	if name == "" {
		name = "yay"
	}
	if runner == nil {
		runner = OSCommandRunner{}
	}
	return &Backend{
		Name:      name,
		Pacman:    "pacman",
		Runner:    runner,
		repoCache: make(map[string]bool),
	}
}

// Passthrough runs the configured backend interactively with the given args.
func (b *Backend) Passthrough(ctx context.Context, args []string) (int, error) {
	return b.Runner.RunInteractive(ctx, b.Name, args)
}

// PendingAURUpgrades queries `<backend> -Qua` and returns the list of AUR
// package names with available upgrades.
func (b *Backend) PendingAURUpgrades(ctx context.Context) ([]string, error) {
	out, exitCode, err := b.Runner.RunCapture(ctx, b.Name, []string{"-Qua"})
	if err != nil {
		// yay and paru exit with status 1 and empty stdout when no AUR upgrades are pending.
		if exitCode == 1 && len(strings.TrimSpace(string(out))) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query pending AUR upgrades via %s -Qua (exit %d): %w", b.Name, exitCode, err)
	}

	var pkgs []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			pkgs = append(pkgs, fields[0])
		}
	}
	return pkgs, nil
}

// preloadSyncRepos loads all official sync repository package names once via
// `pacman -Slq`. If the command fails, syncRepos stays nil and IsRepoPackage
// falls back cleanly to per-package `pacman -Si` lookups.
func (b *Backend) preloadSyncRepos(ctx context.Context) {
	b.syncOnce.Do(func() {
		pacmanBin := b.Pacman
		if pacmanBin == "" {
			pacmanBin = "pacman"
		}
		out, exitCode, err := b.Runner.RunCapture(ctx, pacmanBin, []string{"-Slq"})
		if err != nil || exitCode != 0 {
			return
		}
		repos := make(map[string]bool)
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				repos[line] = true
			}
		}
		b.syncRepos = repos
	})
}

// IsRepoPackage checks whether pkg exists in an official pacman sync repository.
// It first checks the preloaded `pacman -Slq` package list, and falls back to
// `pacman -Si -- <pkg>` (cached) to handle virtual provides or when `-Slq` is unavailable.
func (b *Backend) IsRepoPackage(ctx context.Context, pkg string) bool {
	b.preloadSyncRepos(ctx)
	if b.syncRepos[pkg] {
		return true
	}

	b.repoMu.RLock()
	if cached, ok := b.repoCache[pkg]; ok {
		b.repoMu.RUnlock()
		return cached
	}
	b.repoMu.RUnlock()

	pacmanBin := b.Pacman
	if pacmanBin == "" {
		pacmanBin = "pacman"
	}

	_, exitCode, err := b.Runner.RunCapture(ctx, pacmanBin, []string{"-Si", "--", pkg})
	isRepo := err == nil && exitCode == 0

	b.repoMu.Lock()
	b.repoCache[pkg] = isRepo
	b.repoMu.Unlock()
	return isRepo
}

// InstallApproved hands off execution to `<backend>` with `--answerdiff None`
// and (when skippedPkgs is non-empty) `--ignore <comma-separated skipped>`.
func (b *Backend) InstallApproved(ctx context.Context, originalArgs []string, skippedPkgs []string) (int, error) {
	args := BuildInstallArgs(originalArgs, skippedPkgs)
	return b.Runner.RunInteractive(ctx, b.Name, args)
}

// StripAURPrefix strips an optional "aur/" repo qualifier used by yay/paru
// (e.g. "aur/foo" -> "foo", true).
func StripAURPrefix(target string) (pkg string, explicitAUR bool) {
	if strings.HasPrefix(target, "aur/") {
		return strings.TrimPrefix(target, "aur/"), true
	}
	return target, false
}

// BuildInstallArgs constructs the backend argument list for approved installs/upgrades.
// Positional targets matching skippedPkgs (with or without an "aur/" prefix) are
// removed so yay/paru will not still install or prompt for explicitly skipped targets.
// Extra flags (--answerdiff None, --ignore ...) are inserted before any "--" separator
// so they are never treated as package names.
func BuildInstallArgs(originalArgs []string, skippedPkgs []string) []string {
	var base []string
	if len(originalArgs) == 0 {
		base = []string{"-Syu"}
	} else {
		skipSet := make(map[string]bool, len(skippedPkgs))
		for _, s := range skippedPkgs {
			name, _ := StripAURPrefix(s)
			skipSet[name] = true
		}

		base = make([]string, 0, len(originalArgs))
		afterDoubleDash := false
		for i := 0; i < len(originalArgs); i++ {
			arg := originalArgs[i]
			if afterDoubleDash {
				name, _ := StripAURPrefix(arg)
				if skipSet[name] {
					continue
				}
				base = append(base, arg)
				continue
			}
			if arg == "--" {
				afterDoubleDash = true
				base = append(base, arg)
				continue
			}

			// Long flag (possibly taking the next argument as its value)
			if strings.HasPrefix(arg, "--") {
				base = append(base, arg)
				flagName := arg
				hasEq := false
				if idx := strings.IndexByte(arg, '='); idx != -1 {
					flagName = arg[:idx]
					hasEq = true
				}
				if !hasEq && longFlagsWithValue[flagName] && i+1 < len(originalArgs) {
					i++
					base = append(base, originalArgs[i])
				}
				continue
			}

			// Short flag cluster (possibly taking the next argument as its value)
			if strings.HasPrefix(arg, "-") && len(arg) > 1 {
				base = append(base, arg)
				last := arg[len(arg)-1]
				if shortFlagsWithValue[last] && i+1 < len(originalArgs) {
					i++
					base = append(base, originalArgs[i])
				}
				continue
			}

			// Positional target package name
			name, _ := StripAURPrefix(arg)
			if skipSet[name] {
				continue
			}
			base = append(base, arg)
		}
	}

	hasAnswerDiff := false
	doubleDashIdx := -1
	for i, a := range base {
		if a == "--" {
			doubleDashIdx = i
			break
		}
		if a == "--answerdiff" || strings.HasPrefix(a, "--answerdiff=") {
			hasAnswerDiff = true
		}
	}

	var extra []string
	if !hasAnswerDiff {
		extra = append(extra, "--answerdiff", "None")
	}
	if len(skippedPkgs) > 0 {
		extra = append(extra, "--ignore", strings.Join(skippedPkgs, ","))
	}

	if len(extra) == 0 {
		return base
	}
	if doubleDashIdx == -1 {
		return append(base, extra...)
	}

	out := make([]string, 0, len(base)+len(extra))
	out = append(out, base[:doubleDashIdx]...)
	out = append(out, extra...)
	out = append(out, base[doubleDashIdx:]...)
	return out
}
