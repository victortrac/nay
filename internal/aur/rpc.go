package aur

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultAURRPCURL is the default AUR RPC v5 info endpoint.
	DefaultAURRPCURL = "https://aur.archlinux.org/rpc/v5/info"
	// DefaultRPCBatchSize is the maximum number of package names queried per RPC request.
	DefaultRPCBatchSize = 100
)

// PackageInfo holds AUR package metadata returned by the AUR RPC v5 API.
type PackageInfo struct {
	Name           string   `json:"Name"`
	PackageBase    string   `json:"PackageBase"`
	Version        string   `json:"Version"`
	Description    string   `json:"Description"`
	URL            string   `json:"URL"`
	Maintainer     string   `json:"Maintainer"`
	NumVotes       int      `json:"NumVotes"`
	Popularity     float64  `json:"Popularity"`
	OutOfDate      int64    `json:"OutOfDate"`
	FirstSubmitted int64    `json:"FirstSubmitted"`
	LastModified   int64    `json:"LastModified"`
	Depends        []string `json:"Depends"`
	MakeDepends    []string `json:"MakeDepends"`
	OptDepends     []string `json:"OptDepends"`
	CheckDepends   []string `json:"CheckDepends"`
}

type rpcResponse struct {
	Version     int           `json:"version"`
	Type        string        `json:"type"`
	ResultCount int           `json:"resultcount"`
	Results     []PackageInfo `json:"results"`
	Error       string        `json:"error"`
}

// RPCClient queries the AUR RPC v5 info endpoint.
type RPCClient struct {
	HTTPClient *http.Client
	BaseURL    string
	BatchSize  int
}

// NewRPCClient returns an RPCClient configured with sensible defaults.
func NewRPCClient() *RPCClient {
	return &RPCClient{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		BaseURL:    DefaultAURRPCURL,
		BatchSize:  DefaultRPCBatchSize,
	}
}

func (c *RPCClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *RPCClient) baseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return DefaultAURRPCURL
}

func (c *RPCClient) batchSize() int {
	if c.BatchSize > 0 {
		return c.BatchSize
	}
	return DefaultRPCBatchSize
}

// Info fetches AUR metadata for the given package names, batching requests as needed.
func (c *RPCClient) Info(ctx context.Context, names []string) ([]PackageInfo, error) {
	cleaned := dedupeStrings(names)
	if len(cleaned) == 0 {
		return nil, nil
	}

	batchSize := c.batchSize()
	var results []PackageInfo

	for i := 0; i < len(cleaned); i += batchSize {
		end := i + batchSize
		if end > len(cleaned) {
			end = len(cleaned)
		}
		batch, err := c.fetchBatch(ctx, cleaned[i:end])
		if err != nil {
			return nil, err
		}
		results = append(results, batch...)
	}

	return results, nil
}

func (c *RPCClient) fetchBatch(ctx context.Context, names []string) ([]PackageInfo, error) {
	u, err := url.Parse(c.baseURL())
	if err != nil {
		return nil, fmt.Errorf("aur rpc: invalid base URL %q: %w", c.baseURL(), err)
	}

	q := u.Query()
	for _, name := range names {
		q.Add("arg[]", name)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("aur rpc: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "nay/1.0")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("aur rpc: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("aur rpc: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aur rpc: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed rpcResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("aur rpc: decode response: %w", err)
	}

	if parsed.Type == "error" || parsed.Error != "" {
		msg := parsed.Error
		if msg == "" {
			msg = "unknown AUR RPC error"
		}
		return nil, fmt.Errorf("aur rpc: %s", msg)
	}

	return parsed.Results, nil
}

// StripVersionConstraint removes Arch dependency version constraints (>=, <=, =, >, <)
// and optional descriptions (: ...) from a dependency string.
func StripVersionConstraint(dep string) string {
	dep = strings.TrimSpace(dep)
	if idx := strings.IndexAny(dep, "=<>:"); idx >= 0 {
		dep = dep[:idx]
	}
	return strings.TrimSpace(dep)
}

// ResolveAURDeps recursively resolves Depends, MakeDepends, and CheckDepends for the given
// root package names, skipping packages for which isRepoPkg returns true.
// It strips version constraints, deduplicates packages, handles dependency cycles safely,
// and returns packages in dependency order (dependencies before dependents).
func (c *RPCClient) ResolveAURDeps(ctx context.Context, roots []string, isRepoPkg func(string) bool) ([]PackageInfo, error) {
	isRepo := func(name string) bool {
		if isRepoPkg == nil {
			return false
		}
		return isRepoPkg(name)
	}

	var cleanRoots []string
	seenRoot := make(map[string]bool)
	for _, r := range roots {
		name := StripVersionConstraint(r)
		if name == "" || seenRoot[name] || isRepo(name) {
			continue
		}
		seenRoot[name] = true
		cleanRoots = append(cleanRoots, name)
	}
	if len(cleanRoots) == 0 {
		return nil, nil
	}

	queried := make(map[string]bool)
	pkgs := make(map[string]PackageInfo)
	frontier := append([]string(nil), cleanRoots...)

	for len(frontier) > 0 {
		var toQuery []string
		for _, name := range frontier {
			if queried[name] {
				continue
			}
			queried[name] = true
			toQuery = append(toQuery, name)
		}
		if len(toQuery) == 0 {
			break
		}

		infos, err := c.Info(ctx, toQuery)
		if err != nil {
			return nil, err
		}

		var nextFrontier []string
		queuedNext := make(map[string]bool)
		for _, info := range infos {
			pkgs[info.Name] = info
			for _, dep := range collectRuntimeAndBuildDeps(info) {
				depName := StripVersionConstraint(dep)
				if depName == "" || queried[depName] || queuedNext[depName] || isRepo(depName) {
					continue
				}
				queuedNext[depName] = true
				nextFrontier = append(nextFrontier, depName)
			}
		}
		frontier = nextFrontier
	}

	// Post-order DFS for topological (dependency-first) ordering, cycle-safe.
	const (
		unvisited = 0
		visiting  = 1
		visited   = 2
	)
	state := make(map[string]int, len(pkgs))
	var ordered []PackageInfo

	var visit func(name string)
	visit = func(name string) {
		if state[name] != unvisited {
			return
		}
		info, ok := pkgs[name]
		if !ok {
			return
		}
		state[name] = visiting
		for _, dep := range collectRuntimeAndBuildDeps(info) {
			depName := StripVersionConstraint(dep)
			if depName == "" {
				continue
			}
			if _, exists := pkgs[depName]; exists {
				visit(depName)
			}
		}
		state[name] = visited
		ordered = append(ordered, info)
	}

	for _, r := range cleanRoots {
		visit(r)
	}
	// Visit any remaining packages returned by RPC (e.g. if canonical name differed from root alias).
	for name := range pkgs {
		visit(name)
	}

	return ordered, nil
}

func collectRuntimeAndBuildDeps(info PackageInfo) []string {
	total := len(info.Depends) + len(info.MakeDepends) + len(info.CheckDepends)
	if total == 0 {
		return nil
	}
	deps := make([]string, 0, total)
	deps = append(deps, info.Depends...)
	deps = append(deps, info.MakeDepends...)
	deps = append(deps, info.CheckDepends...)
	return deps
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
