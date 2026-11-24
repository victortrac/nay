package aur

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// DefaultAURGitBaseURL is the default base URL for AUR git repositories.
	DefaultAURGitBaseURL = "https://aur.archlinux.org"
	// DefaultMaxFileBytes is the maximum number of bytes read from any single repo file (64 KiB).
	DefaultMaxFileBytes int64 = 64 * 1024
	// DefaultMaxDiffBytes is the maximum number of bytes kept from git diff output (128 KiB).
	DefaultMaxDiffBytes = 128 * 1024
)

// RepoFile represents a single text file inside an AUR git repository.
type RepoFile struct {
	Path      string
	Content   string
	Truncated bool
}

// RepoSnapshot captures the synced state of an AUR git repository at HEAD.
type RepoSnapshot struct {
	PackageBase string
	RepoDir     string
	CommitSHA   string
	Diff        string
	Files       []RepoFile
}

// GitFetcher clones and updates AUR git repositories into a local cache directory.
type GitFetcher struct {
	BaseURL      string
	MaxFileBytes int64
	MaxDiffBytes int
}

// NewGitFetcher returns a GitFetcher configured with default settings.
func NewGitFetcher() *GitFetcher {
	return &GitFetcher{
		BaseURL:      DefaultAURGitBaseURL,
		MaxFileBytes: DefaultMaxFileBytes,
		MaxDiffBytes: DefaultMaxDiffBytes,
	}
}

func (g *GitFetcher) baseURL() string {
	if g.BaseURL != "" {
		return g.BaseURL
	}
	return DefaultAURGitBaseURL
}

func (g *GitFetcher) maxFileBytes() int64 {
	if g.MaxFileBytes > 0 {
		return g.MaxFileBytes
	}
	return DefaultMaxFileBytes
}

func (g *GitFetcher) maxDiffBytes() int {
	if g.MaxDiffBytes > 0 {
		return g.MaxDiffBytes
	}
	return DefaultMaxDiffBytes
}

// SyncRepo clones or fetches <BaseURL>/<pkgBase>.git into <cacheDir>/<pkgBase>,
// resolves HEAD, reads all non-binary text files in the repository, and computes
// git diff <prevCommitSHA>..HEAD when prevCommitSHA is provided and differs from HEAD.
func (g *GitFetcher) SyncRepo(ctx context.Context, cacheDir, pkgBase, prevCommitSHA string) (*RepoSnapshot, error) {
	if err := validatePkgBase(pkgBase); err != nil {
		return nil, err
	}
	if cacheDir == "" {
		return nil, fmt.Errorf("aur git: cacheDir must not be empty")
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("aur git: create cache dir: %w", err)
	}

	repoDir := filepath.Join(cacheDir, pkgBase)
	repoURL := strings.TrimRight(g.baseURL(), "/") + "/" + pkgBase + ".git"

	if _, err := os.Stat(filepath.Join(repoDir, ".git")); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("aur git: stat repo %q: %w", repoDir, err)
		}
		if _, err := runGit(ctx, "", "clone", "--quiet", repoURL, repoDir); err != nil {
			return nil, fmt.Errorf("aur git: clone %s: %w", repoURL, err)
		}
	} else {
		if _, err := runGit(ctx, repoDir, "fetch", "--quiet", "origin"); err != nil {
			return nil, fmt.Errorf("aur git: fetch %s: %w", pkgBase, err)
		}
		// Reset working tree to upstream tracking branch (or FETCH_HEAD as fallback)
		// so force-pushes and both main/master default branches are handled cleanly.
		if _, err := runGit(ctx, repoDir, "reset", "--hard", "--quiet", "@{u}"); err != nil {
			if _, err2 := runGit(ctx, repoDir, "reset", "--hard", "--quiet", "FETCH_HEAD"); err2 != nil {
				return nil, fmt.Errorf("aur git: reset %s: %w", pkgBase, err2)
			}
		}
		_, _ = runGit(ctx, repoDir, "clean", "-fdx", "-q")
	}

	headOut, err := runGit(ctx, repoDir, "rev-parse", "HEAD")
	if err != nil {
		return nil, fmt.Errorf("aur git: rev-parse HEAD for %s: %w", pkgBase, err)
	}
	commitSHA := strings.TrimSpace(headOut)

	var diffText string
	prevCommitSHA = strings.TrimSpace(prevCommitSHA)
	if prevCommitSHA != "" && prevCommitSHA != commitSHA && isValidCommitSHA(prevCommitSHA) {
		if _, err := runGit(ctx, repoDir, "cat-file", "-e", prevCommitSHA+"^{commit}"); err == nil {
			rawDiff, err := runGit(ctx, repoDir, "diff", prevCommitSHA+"..HEAD")
			if err != nil {
				return nil, fmt.Errorf("aur git: diff %s..HEAD for %s: %w", prevCommitSHA, pkgBase, err)
			}
			diffText = capDiff(rawDiff, g.maxDiffBytes())
		}
	}

	files, err := readRepoFiles(repoDir, g.maxFileBytes())
	if err != nil {
		return nil, fmt.Errorf("aur git: read files for %s: %w", pkgBase, err)
	}

	return &RepoSnapshot{
		PackageBase: pkgBase,
		RepoDir:     repoDir,
		CommitSHA:   commitSHA,
		Diff:        diffText,
		Files:       files,
	}, nil
}

func readRepoFiles(repoDir string, maxBytes int64) ([]RepoFile, error) {
	var files []RepoFile

	err := filepath.WalkDir(repoDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip symlinks and other non-regular files to avoid escaping repoDir.
		if !d.Type().IsRegular() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, maxBytes+1))
		closeErr := f.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}

		if isBinary(data) {
			return nil
		}

		truncated := false
		if int64(len(data)) > maxBytes {
			data = data[:maxBytes]
			truncated = true
		}

		rel, err := filepath.Rel(repoDir, path)
		if err != nil {
			return err
		}

		files = append(files, RepoFile{
			Path:      filepath.ToSlash(rel),
			Content:   string(data),
			Truncated: truncated,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

func isBinary(data []byte) bool {
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	return bytes.IndexByte(sample, 0) != -1
}

func capDiff(diff string, maxBytes int) string {
	if maxBytes <= 0 || len(diff) <= maxBytes {
		return diff
	}
	const suffix = "\n... [diff truncated]"
	if maxBytes <= len(suffix) {
		return diff[:maxBytes]
	}
	return diff[:maxBytes-len(suffix)] + suffix
}

func validatePkgBase(pkgBase string) error {
	if pkgBase == "" {
		return fmt.Errorf("aur git: pkgBase must not be empty")
	}
	if strings.ContainsAny(pkgBase, `/\`) || strings.Contains(pkgBase, "..") || strings.HasPrefix(pkgBase, "-") {
		return fmt.Errorf("aur git: invalid pkgBase %q", pkgBase)
	}
	return nil
}

func isValidCommitSHA(sha string) bool {
	if len(sha) < 7 || len(sha) > 40 {
		return false
	}
	for i := 0; i < len(sha); i++ {
		c := sha[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg != "" {
			return "", fmt.Errorf("%w: %s", err, errMsg)
		}
		return "", err
	}
	return stdout.String(), nil
}
