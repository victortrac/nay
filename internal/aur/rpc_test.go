package aur

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestStripVersionConstraint(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"foo", "foo"},
		{"foo>=1.2.3", "foo"},
		{"foo<=1.2.3-1", "foo"},
		{"foo=2.0", "foo"},
		{"foo>1.0", "foo"},
		{"foo<3.0", "foo"},
		{"foo: optional support", "foo"},
		{"  bar >= 2.0  ", "bar"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := StripVersionConstraint(tc.in); got != tc.want {
			t.Errorf("StripVersionConstraint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRPCClientInfoAndBatching(t *testing.T) {
	db := map[string]PackageInfo{
		"pkg-a": {
			Name:           "pkg-a",
			PackageBase:    "pkg-a",
			Version:        "1.0.0-1",
			Description:    "Package A",
			URL:            "https://example.com/a",
			Maintainer:     "alice",
			NumVotes:       42,
			Popularity:     1.25,
			OutOfDate:      0,
			FirstSubmitted: 1700000000,
			LastModified:   1700001000,
			Depends:        []string{"glibc"},
		},
		"pkg-b": {
			Name:        "pkg-b",
			PackageBase: "pkg-b-base",
			Version:     "2.0.0-1",
			OutOfDate:   1700002000,
		},
		"pkg-c": {
			Name:        "pkg-c",
			PackageBase: "pkg-c",
			Version:     "3.0.0-1",
		},
	}

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		args := r.URL.Query()["arg[]"]
		if len(args) > 2 {
			t.Errorf("batch size exceeded: got %d args", len(args))
		}
		var results []PackageInfo
		for _, name := range args {
			if pkg, ok := db[name]; ok {
				results = append(results, pkg)
			}
		}
		resp := rpcResponse{
			Version:     5,
			Type:        "multiinfo",
			ResultCount: len(results),
			Results:     results,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := &RPCClient{
		HTTPClient: srv.Client(),
		BaseURL:    srv.URL,
		BatchSize:  2,
	}

	got, err := client.Info(context.Background(), []string{"pkg-a", "pkg-b", "pkg-a", "pkg-c", "missing", ""})
	if err != nil {
		t.Fatalf("Info() unexpected error: %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("expected 2 batched requests for 4 unique names with BatchSize=2, got %d", requests.Load())
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 packages, got %d: %+v", len(got), got)
	}
	if got[0].Name != "pkg-a" || got[0].NumVotes != 42 || got[0].Maintainer != "alice" {
		t.Errorf("unexpected pkg-a metadata: %+v", got[0])
	}
	if got[1].Name != "pkg-b" || got[1].OutOfDate != 1700002000 || got[1].PackageBase != "pkg-b-base" {
		t.Errorf("unexpected pkg-b metadata: %+v", got[1])
	}
}

func TestRPCClientInfoEmptyAndErrors(t *testing.T) {
	var called atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		mode := r.URL.Query().Get("arg[]")
		switch mode {
		case "http500":
			http.Error(w, "internal error", http.StatusInternalServerError)
		case "rpcerr":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":5,"type":"error","resultcount":0,"results":[],"error":"Too many package results."}`))
		case "nullfields":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"orphan","PackageBase":"orphan","Version":"1-1","Maintainer":null,"OutOfDate":null,"URL":null}]}`))
		}
	}))
	defer srv.Close()

	client := &RPCClient{HTTPClient: srv.Client(), BaseURL: srv.URL}

	// Empty input should not make any HTTP call.
	got, err := client.Info(context.Background(), nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("Info(nil) = (%v, %v), want (nil, nil)", got, err)
	}
	if called.Load() {
		t.Fatalf("expected no HTTP request for empty input")
	}

	if _, err := client.Info(context.Background(), []string{"http500"}); err == nil {
		t.Errorf("expected error on HTTP 500")
	}

	if _, err := client.Info(context.Background(), []string{"rpcerr"}); err == nil {
		t.Errorf("expected error on AUR RPC error response")
	}

	pkgs, err := client.Info(context.Background(), []string{"nullfields"})
	if err != nil {
		t.Fatalf("Info(nullfields) unexpected error: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Maintainer != "" || pkgs[0].OutOfDate != 0 {
		t.Errorf("unexpected nullfields decode: %+v", pkgs)
	}
}

func TestResolveAURDepsDiamondAndFiltering(t *testing.T) {
	// Graph:
	//   app -> lib-b>=1.0 (Depends), tool-c=2.0 (MakeDepends), check-e (CheckDepends), opt-z (OptDepends, ignored), glibc (repo)
	//   lib-b -> common-d<5.0 (Depends)
	//   tool-c -> common-d (Depends), virtual-prov (not in AUR)
	//   check-e -> common-d (Depends)
	//   common-d -> bash (repo)
	db := map[string]PackageInfo{
		"app": {
			Name:         "app",
			PackageBase:  "app",
			Depends:      []string{"lib-b>=1.0", "glibc>=2.38"},
			MakeDepends:  []string{"tool-c=2.0"},
			CheckDepends: []string{"check-e"},
			OptDepends:   []string{"opt-z: optional feature"},
		},
		"lib-b": {
			Name:        "lib-b",
			PackageBase: "lib-b",
			Depends:     []string{"common-d<5.0"},
		},
		"tool-c": {
			Name:        "tool-c",
			PackageBase: "tool-c",
			Depends:     []string{"common-d", "virtual-prov"},
		},
		"check-e": {
			Name:        "check-e",
			PackageBase: "check-e",
			Depends:     []string{"common-d"},
		},
		"common-d": {
			Name:        "common-d",
			PackageBase: "common-d",
			Depends:     []string{"bash"},
		},
		"opt-z": {
			Name:        "opt-z",
			PackageBase: "opt-z",
		},
	}

	srv := newMockAURServer(t, db)
	defer srv.Close()

	client := &RPCClient{HTTPClient: srv.Client(), BaseURL: srv.URL}
	repoPkgs := map[string]bool{"glibc": true, "bash": true}

	got, err := client.ResolveAURDeps(context.Background(), []string{"app>=1.0", "glibc"}, func(name string) bool {
		return repoPkgs[name]
	})
	if err != nil {
		t.Fatalf("ResolveAURDeps() error: %v", err)
	}

	names := make([]string, len(got))
	pos := make(map[string]int, len(got))
	for i, p := range got {
		names[i] = p.Name
		pos[p.Name] = i
	}

	if len(names) != 5 {
		t.Fatalf("expected 5 AUR packages, got %d: %v", len(names), names)
	}
	if _, hasOpt := pos["opt-z"]; hasOpt {
		t.Errorf("OptDepends package opt-z should not be resolved")
	}
	// Verify dependency order: common-d before lib-b, tool-c, check-e; all before app.
	for _, parent := range []string{"lib-b", "tool-c", "check-e"} {
		if pos["common-d"] >= pos[parent] {
			t.Errorf("expected common-d before %s, order: %v", parent, names)
		}
		if pos[parent] >= pos["app"] {
			t.Errorf("expected %s before app, order: %v", parent, names)
		}
	}
}

func TestResolveAURDepsCycleSafe(t *testing.T) {
	db := map[string]PackageInfo{
		"cyc-a": {
			Name:        "cyc-a",
			PackageBase: "cyc-a",
			Depends:     []string{"cyc-b", "cyc-a"},
		},
		"cyc-b": {
			Name:        "cyc-b",
			PackageBase: "cyc-b",
			Depends:     []string{"cyc-a"},
		},
	}

	srv := newMockAURServer(t, db)
	defer srv.Close()

	client := &RPCClient{HTTPClient: srv.Client(), BaseURL: srv.URL}
	got, err := client.ResolveAURDeps(context.Background(), []string{"cyc-a"}, nil)
	if err != nil {
		t.Fatalf("ResolveAURDeps() cycle error: %v", err)
	}

	var names []string
	for _, p := range got {
		names = append(names, p.Name)
	}
	want := []string{"cyc-b", "cyc-a"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("cycle order = %v, want %v", names, want)
	}
}

func newMockAURServer(t *testing.T, db map[string]PackageInfo) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		args := r.URL.Query()["arg[]"]
		var results []PackageInfo
		for _, name := range args {
			if pkg, ok := db[name]; ok {
				results = append(results, pkg)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rpcResponse{
			Version:     5,
			Type:        "multiinfo",
			ResultCount: len(results),
			Results:     results,
		})
	}))
}
