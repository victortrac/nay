package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Entry represents a cached audit result for a specific (Package, CommitSHA, Model) tuple.
type Entry struct {
	Package     string    `json:"package"`
	CommitSHA   string    `json:"commit_sha"`
	Model       string    `json:"model"`
	Verdict     string    `json:"verdict"`
	Summary     string    `json:"summary"`
	Findings    []string  `json:"findings,omitempty"`
	Reasoning   string    `json:"reasoning,omitempty"`
	StaticFlags []string  `json:"static_flags,omitempty"`
	AuditedAt   time.Time `json:"audited_at"`
}

type entryKey struct {
	pkg       string
	commitSHA string
	model     string
}

type diskFormat struct {
	Version     int               `json:"version"`
	Entries     []Entry           `json:"entries"`
	LastCommits map[string]string `json:"last_commits,omitempty"`
}

// Store is a thread-safe, JSON-backed audit cache persisted atomically to disk.
type Store struct {
	mu          sync.RWMutex
	path        string
	entries     map[entryKey]Entry
	lastCommits map[string]string
}

// Open loads an existing audit cache from path or initializes a new empty store
// if the file does not exist.
func Open(path string) (*Store, error) {
	s := &Store{
		path:        path,
		entries:     make(map[entryKey]Entry),
		lastCommits: make(map[string]string),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, fmt.Errorf("read audit cache %q: %w", path, err)
	}

	if strings.TrimSpace(string(data)) == "" {
		return s, nil
	}

	var df diskFormat
	if err := json.Unmarshal(data, &df); err != nil {
		return nil, fmt.Errorf("parse audit cache %q: %w", path, err)
	}

	for _, e := range df.Entries {
		k := entryKey{pkg: e.Package, commitSHA: e.CommitSHA, model: e.Model}
		s.entries[k] = cloneEntry(e)
	}
	for pkg, sha := range df.LastCommits {
		s.lastCommits[pkg] = sha
	}

	return s, nil
}

// Get retrieves a cached Entry for (pkg, commitSHA, model).
// The returned Entry is a copy safe for caller mutation.
func (s *Store) Get(pkg, commitSHA, model string) (*Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, ok := s.entries[entryKey{pkg: pkg, commitSHA: commitSHA, model: model}]
	if !ok {
		return nil, false
	}
	cp := cloneEntry(e)
	return &cp, true
}

// LastCommit returns the most recently audited commit SHA for pkg, or "" if unknown.
func (s *Store) LastCommit(pkg string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastCommits[pkg]
}

// Put stores entry in memory, updates the last audited commit for entry.Package,
// and atomically persists the cache to disk.
func (s *Store) Put(entry Entry) error {
	if entry.AuditedAt.IsZero() {
		entry.AuditedAt = time.Now().UTC()
	}
	stored := cloneEntry(entry)

	s.mu.Lock()
	defer s.mu.Unlock()

	k := entryKey{pkg: stored.Package, commitSHA: stored.CommitSHA, model: stored.Model}
	s.entries[k] = stored
	if stored.Package != "" && stored.CommitSHA != "" {
		s.lastCommits[stored.Package] = stored.CommitSHA
	}

	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create cache dir %q: %w", dir, err)
	}

	entries := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Package != entries[j].Package {
			return entries[i].Package < entries[j].Package
		}
		if entries[i].CommitSHA != entries[j].CommitSHA {
			return entries[i].CommitSHA < entries[j].CommitSHA
		}
		return entries[i].Model < entries[j].Model
	})

	df := diskFormat{
		Version:     1,
		Entries:     entries,
		LastCommits: s.lastCommits,
	}

	data, err := json.MarshalIndent(df, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal audit cache: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".audits-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp cache file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp cache file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp cache file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp cache file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod temp cache file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp cache file: %w", err)
	}
	return nil
}

func cloneEntry(e Entry) Entry {
	cp := e
	if e.Findings != nil {
		cp.Findings = make([]string, len(e.Findings))
		copy(cp.Findings, e.Findings)
	}
	if e.StaticFlags != nil {
		cp.StaticFlags = make([]string, len(e.StaticFlags))
		copy(cp.StaticFlags, e.StaticFlags)
	}
	return cp
}
