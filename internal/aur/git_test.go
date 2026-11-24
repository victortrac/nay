package aur

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitFetcherSyncRepoCloneAndUpdate(t *testing.T) {
	remoteBase := t.TempDir()
	workDir := t.TempDir()
	cacheDir := t.TempDir()

	pkgBase := "sample-pkg"
	bareRepo := filepath.Join(remoteBase, pkgBase+".git")
	mustRunGit(t, "", "init", "--bare", bareRepo)

	// Clone bare repo into a temp working tree to author commits.
	authorDir := filepath.Join(workDir, "author")
	mustRunGit(t, "", "clone", bareRepo, authorDir)
	mustRunGit(t, authorDir, "config", "user.name", "Test Author")
	mustRunGit(t, authorDir, "config", "user.email", "author@example.com")

	// Commit 1: PKGBUILD, nested patch, binary file, large file, and symlink.
	writeTestFile(t, filepath.Join(authorDir, "PKGBUILD"), "pkgname=sample-pkg\npkgver=1.0.0\n")
	writeTestFile(t, filepath.Join(authorDir, ".SRCINFO"), "pkgbase = sample-pkg\n")
	writeTestFile(t, filepath.Join(authorDir, "patches", "fix.patch"), "--- a/foo\n+++ b/foo\n")
	writeTestBytes(t, filepath.Join(authorDir, "icon.bin"), []byte{0x89, 'P', 'N', 'G', 0x00, 0x01, 0x02})
	writeTestFile(t, filepath.Join(authorDir, "big.txt"), strings.Repeat("A", 200))
	if err := os.Symlink("/etc/hosts", filepath.Join(authorDir, "escape.link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	mustRunGit(t, authorDir, "add", "-A")
	mustRunGit(t, authorDir, "commit", "-m", "initial commit")
	mustRunGit(t, authorDir, "push", "origin", "HEAD")
	commit1 := strings.TrimSpace(mustRunGit(t, authorDir, "rev-parse", "HEAD"))

	fetcher := &GitFetcher{
		BaseURL:      remoteBase,
		MaxFileBytes: 64,
		MaxDiffBytes: 4096,
	}

	// First sync: fresh clone, no previous commit.
	snap1, err := fetcher.SyncRepo(context.Background(), cacheDir, pkgBase, "")
	if err != nil {
		t.Fatalf("SyncRepo (clone) failed: %v", err)
	}
	if snap1.PackageBase != pkgBase {
		t.Errorf("PackageBase = %q, want %q", snap1.PackageBase, pkgBase)
	}
	if snap1.RepoDir != filepath.Join(cacheDir, pkgBase) {
		t.Errorf("RepoDir = %q, want %q", snap1.RepoDir, filepath.Join(cacheDir, pkgBase))
	}
	if snap1.CommitSHA != commit1 {
		t.Errorf("CommitSHA = %q, want %q", snap1.CommitSHA, commit1)
	}
	if snap1.Diff != "" {
		t.Errorf("expected empty Diff on initial clone, got %q", snap1.Diff)
	}

	fileMap := make(map[string]RepoFile, len(snap1.Files))
	for _, f := range snap1.Files {
		fileMap[f.Path] = f
	}
	if _, ok := fileMap["icon.bin"]; ok {
		t.Errorf("binary file icon.bin should have been skipped")
	}
	if _, ok := fileMap["escape.link"]; ok {
		t.Errorf("symlink escape.link should have been skipped")
	}
	for p := range fileMap {
		if strings.HasPrefix(p, ".git/") || p == ".git" {
			t.Errorf(".git file should have been excluded: %s", p)
		}
	}
	if f, ok := fileMap["PKGBUILD"]; !ok || f.Truncated || !strings.Contains(f.Content, "pkgver=1.0.0") {
		t.Errorf("unexpected PKGBUILD file: %+v", f)
	}
	if f, ok := fileMap["patches/fix.patch"]; !ok || f.Truncated {
		t.Errorf("unexpected patches/fix.patch file: %+v", f)
	}
	if f, ok := fileMap["big.txt"]; !ok || !f.Truncated || len(f.Content) != 64 {
		t.Errorf("expected big.txt truncated to 64 bytes, got %+v (len=%d)", f, len(f.Content))
	}

	// Commit 2: update PKGBUILD and add .install script.
	writeTestFile(t, filepath.Join(authorDir, "PKGBUILD"), "pkgname=sample-pkg\npkgver=2.0.0\n")
	writeTestFile(t, filepath.Join(authorDir, "sample-pkg.install"), "post_install() { echo hi; }\n")
	mustRunGit(t, authorDir, "add", "-A")
	mustRunGit(t, authorDir, "commit", "-m", "bump to 2.0.0")
	mustRunGit(t, authorDir, "push", "origin", "HEAD")
	commit2 := strings.TrimSpace(mustRunGit(t, authorDir, "rev-parse", "HEAD"))

	// Second sync: fetches update and computes diff from commit1..commit2.
	snap2, err := fetcher.SyncRepo(context.Background(), cacheDir, pkgBase, commit1)
	if err != nil {
		t.Fatalf("SyncRepo (fetch) failed: %v", err)
	}
	if snap2.CommitSHA != commit2 {
		t.Errorf("CommitSHA = %q, want %q", snap2.CommitSHA, commit2)
	}
	if !strings.Contains(snap2.Diff, "-pkgver=1.0.0") || !strings.Contains(snap2.Diff, "+pkgver=2.0.0") {
		t.Errorf("expected diff to contain pkgver change, got:\n%s", snap2.Diff)
	}
	if !strings.Contains(snap2.Diff, "post_install()") {
		t.Errorf("expected diff to contain new .install script, got:\n%s", snap2.Diff)
	}

	// Sync when prevCommitSHA == HEAD should produce empty Diff.
	snapSame, err := fetcher.SyncRepo(context.Background(), cacheDir, pkgBase, commit2)
	if err != nil {
		t.Fatalf("SyncRepo (same SHA) failed: %v", err)
	}
	if snapSame.Diff != "" {
		t.Errorf("expected empty Diff when prevCommitSHA == HEAD, got %q", snapSame.Diff)
	}

	// Sync with an unknown valid SHA should not fail and should return empty Diff.
	snapUnknown, err := fetcher.SyncRepo(context.Background(), cacheDir, pkgBase, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	if err != nil {
		t.Fatalf("SyncRepo (unknown SHA) failed: %v", err)
	}
	if snapUnknown.Diff != "" {
		t.Errorf("expected empty Diff for unknown prevCommitSHA, got %q", snapUnknown.Diff)
	}

	// Diff truncation test.
	smallDiffFetcher := &GitFetcher{
		BaseURL:      remoteBase,
		MaxFileBytes: 64 * 1024,
		MaxDiffBytes: 40,
	}
	snapTrunc, err := smallDiffFetcher.SyncRepo(context.Background(), cacheDir, pkgBase, commit1)
	if err != nil {
		t.Fatalf("SyncRepo (truncated diff) failed: %v", err)
	}
	if len(snapTrunc.Diff) > 40 || !strings.HasSuffix(snapTrunc.Diff, "... [diff truncated]") {
		t.Errorf("expected truncated diff <= 40 bytes, got len=%d %q", len(snapTrunc.Diff), snapTrunc.Diff)
	}
}

func TestGitFetcherInvalidPkgBase(t *testing.T) {
	fetcher := NewGitFetcher()
	cacheDir := t.TempDir()

	for _, bad := range []string{"", "../evil", "a/b", `a\b`, "-leading-dash"} {
		if _, err := fetcher.SyncRepo(context.Background(), cacheDir, bad, ""); err == nil {
			t.Errorf("SyncRepo(%q) expected error, got nil", bad)
		}
	}
}

func mustRunGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
	return string(out)
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	writeTestBytes(t, path, []byte(content))
}

func writeTestBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
