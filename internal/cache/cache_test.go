package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestOpenMissingAndPutGetPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audits.json")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open missing file failed: %v", err)
	}
	if _, ok := s.Get("ripgrep-git", "abc123", "gpt-4.1-mini"); ok {
		t.Fatal("expected cache miss on empty store")
	}
	if got := s.LastCommit("ripgrep-git"); got != "" {
		t.Fatalf("expected empty LastCommit, got %q", got)
	}

	now := time.Date(2026, 11, 23, 22, 0, 0, 0, time.UTC)
	e1 := Entry{
		Package:     "ripgrep-git",
		CommitSHA:   "abc123",
		Model:       "gpt-4.1-mini",
		Verdict:     "SAFE",
		Summary:     "Looks clean.",
		Findings:    []string{"standard cargo build"},
		Reasoning:   "Builds from official upstream repo.",
		StaticFlags: []string{},
		AuditedAt:   now,
	}
	if err := s.Put(e1); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	got, ok := s.Get("ripgrep-git", "abc123", "gpt-4.1-mini")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if !reflect.DeepEqual(*got, e1) {
		t.Fatalf("entry mismatch:\ngot:  %+v\nwant: %+v", *got, e1)
	}
	if lc := s.LastCommit("ripgrep-git"); lc != "abc123" {
		t.Fatalf("LastCommit = %q, want abc123", lc)
	}

	// Mutating returned entry must not affect store.
	got.Findings[0] = "mutated"
	got2, _ := s.Get("ripgrep-git", "abc123", "gpt-4.1-mini")
	if got2.Findings[0] != "standard cargo build" {
		t.Fatal("store was mutated through returned copy")
	}

	// Different model is a miss.
	if _, ok := s.Get("ripgrep-git", "abc123", "gemini-2.5-pro"); ok {
		t.Fatal("expected miss for different model")
	}

	// Newer commit updates LastCommit.
	e2 := e1
	e2.CommitSHA = "def456"
	e2.Verdict = "WARN"
	if err := s.Put(e2); err != nil {
		t.Fatalf("Put e2 failed: %v", err)
	}
	if lc := s.LastCommit("ripgrep-git"); lc != "def456" {
		t.Fatalf("LastCommit = %q, want def456", lc)
	}

	// Re-open from disk and verify persistence.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open failed: %v", err)
	}
	reloaded, ok := s2.Get("ripgrep-git", "def456", "gpt-4.1-mini")
	if !ok {
		t.Fatal("expected reloaded hit for def456")
	}
	if reloaded.Verdict != "WARN" {
		t.Fatalf("reloaded verdict = %q, want WARN", reloaded.Verdict)
	}
	if lc := s2.LastCommit("ripgrep-git"); lc != "def456" {
		t.Fatalf("reloaded LastCommit = %q, want def456", lc)
	}
}

func TestOpenCorruptJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audits.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("expected error for corrupt JSON")
	}
}

func TestConcurrentAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audits.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pkg := fmt.Sprintf("pkg-%d", id)
			sha := fmt.Sprintf("sha-%d", id)
			if err := s.Put(Entry{
				Package:   pkg,
				CommitSHA: sha,
				Model:     "test-model",
				Verdict:   "SAFE",
				Summary:   "ok",
			}); err != nil {
				t.Errorf("Put(%s): %v", pkg, err)
				return
			}
			if _, ok := s.Get(pkg, sha, "test-model"); !ok {
				t.Errorf("Get(%s) missed after Put", pkg)
			}
			if lc := s.LastCommit(pkg); lc != sha {
				t.Errorf("LastCommit(%s) = %q, want %q", pkg, lc, sha)
			}
		}(i)
	}
	wg.Wait()

	// Verify file on disk is valid JSON containing all 16 entries.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open after concurrent writes failed: %v", err)
	}
	for i := 0; i < 16; i++ {
		pkg := fmt.Sprintf("pkg-%d", i)
		sha := fmt.Sprintf("sha-%d", i)
		if _, ok := s2.Get(pkg, sha, "test-model"); !ok {
			t.Errorf("missing %s after reload", pkg)
		}
	}
}
