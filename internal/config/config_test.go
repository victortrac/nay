package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	if err := WriteDefault(path, false); err != nil {
		t.Fatalf("WriteDefault failed: %v", err)
	}

	// Second call without force should fail with os.ErrExist.
	if err := WriteDefault(path, false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected os.ErrExist on duplicate WriteDefault, got: %v", err)
	}

	// With force=true it should succeed.
	if err := WriteDefault(path, true); err != nil {
		t.Fatalf("WriteDefault(force=true) failed: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	want := DefaultConfig()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\ngot:  %+v\nwant: %+v", got, want)
	}
}

func TestLoadMissingReturnsDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.toml")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load missing file returned error: %v", err)
	}
	if !reflect.DeepEqual(got, DefaultConfig()) {
		t.Fatalf("expected DefaultConfig, got %+v", got)
	}
}

func TestParseTOMLCustomValues(t *testing.T) {
	tomlData := "\xef\xbb\xbf" + `
# Top comment
backend = "paru" # inline comment
auto_approve_safe = true
concurrency = 8

[llm]
provider = "gemini"
model = "gemini-2.5-pro"
base_url = 'https://example.com/v1#not-a-comment'
api_key_env = "MY_CUSTOM_KEY"
timeout_seconds = 120
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(tomlData), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Backend != "paru" {
		t.Errorf("Backend = %q, want paru", cfg.Backend)
	}
	if !cfg.AutoApproveSafe {
		t.Errorf("AutoApproveSafe = false, want true")
	}
	if cfg.Concurrency != 8 {
		t.Errorf("Concurrency = %d, want 8", cfg.Concurrency)
	}
	if cfg.LLM.Provider != "gemini" {
		t.Errorf("Provider = %q, want gemini", cfg.LLM.Provider)
	}
	if cfg.LLM.Model != "gemini-2.5-pro" {
		t.Errorf("Model = %q, want gemini-2.5-pro", cfg.LLM.Model)
	}
	if cfg.LLM.BaseURL != "https://example.com/v1#not-a-comment" {
		t.Errorf("BaseURL = %q, want https://example.com/v1#not-a-comment", cfg.LLM.BaseURL)
	}
	if cfg.LLM.APIKeyEnv != "MY_CUSTOM_KEY" {
		t.Errorf("APIKeyEnv = %q, want MY_CUSTOM_KEY", cfg.LLM.APIKeyEnv)
	}
	if cfg.LLM.TimeoutSeconds != 120 {
		t.Errorf("TimeoutSeconds = %d, want 120", cfg.LLM.TimeoutSeconds)
	}
}

func TestProviderDefaultAPIKeyEnv(t *testing.T) {
	tests := []struct {
		provider string
		wantEnv  string
	}{
		{"gemini", "GEMINI_API_KEY"},
		{"anthropic", "ANTHROPIC_API_KEY"},
		{"openai-compatible", "OPENAI_API_KEY"},
	}
	for _, tc := range tests {
		cfg, err := parseTOML("[llm]\nprovider = \"" + tc.provider + "\"\n")
		if err != nil {
			t.Fatalf("provider %s: %v", tc.provider, err)
		}
		if cfg.LLM.APIKeyEnv != tc.wantEnv {
			t.Errorf("provider %s: APIKeyEnv = %q, want %q", tc.provider, cfg.LLM.APIKeyEnv, tc.wantEnv)
		}
	}
}

func TestParseTOMLErrors(t *testing.T) {
	badInputs := []struct {
		name string
		toml string
	}{
		{"invalid backend", `backend = "pacman"`},
		{"zero concurrency", `concurrency = 0`},
		{"bad bool", `auto_approve_safe = maybe`},
		{"bad int", `concurrency = "four"`},
		{"unknown section", "[other]\nfoo = \"bar\""},
		{"unknown key", `unknown_key = "x"`},
		{"unknown llm key", "[llm]\nunknown = \"x\""},
		{"invalid provider", "[llm]\nprovider = \"bedrock\""},
		{"unclosed section", "[llm"},
		{"missing equals", "backend yay"},
		{"unquoted string", "backend = yay"},
		{"negative timeout", "[llm]\ntimeout_seconds = -5"},
	}
	for _, tc := range badInputs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseTOML(tc.toml); err == nil {
				t.Errorf("expected error for %q, got nil", tc.name)
			}
		})
	}
}

func TestResolveAPIKey(t *testing.T) {
	t.Setenv("TEST_NAY_API_KEY", "secret-123")
	cfg := DefaultConfig()
	cfg.LLM.APIKeyEnv = "TEST_NAY_API_KEY"
	if got := cfg.ResolveAPIKey(); got != "secret-123" {
		t.Errorf("ResolveAPIKey = %q, want secret-123", got)
	}

	// Direct api_key takes precedence over api_key_env.
	cfg.LLM.APIKey = "direct-secret-456"
	if got := cfg.ResolveAPIKey(); got != "direct-secret-456" {
		t.Errorf("ResolveAPIKey with direct APIKey = %q, want direct-secret-456", got)
	}

	// Whitespace-only direct api_key falls back to api_key_env.
	cfg.LLM.APIKey = "   "
	if got := cfg.ResolveAPIKey(); got != "secret-123" {
		t.Errorf("ResolveAPIKey with whitespace APIKey = %q, want secret-123", got)
	}

	// Empty direct api_key and empty api_key_env returns empty string.
	cfg.LLM.APIKey = ""
	cfg.LLM.APIKeyEnv = ""
	if got := cfg.ResolveAPIKey(); got != "" {
		t.Errorf("ResolveAPIKey with empty env = %q, want empty", got)
	}

	var nilCfg *Config
	if got := nilCfg.ResolveAPIKey(); got != "" {
		t.Errorf("nil Config ResolveAPIKey = %q, want empty", got)
	}
}

func TestParseTOMLDirectAPIKey(t *testing.T) {
	t.Setenv("TEST_NAY_FALLBACK_KEY", "from-env")

	tomlData := `
[llm]
provider = "gemini"
model = "gemini-2.5-pro"
api_key = "direct-from-toml"
api_key_env = "TEST_NAY_FALLBACK_KEY"
`
	cfg, err := parseTOML(tomlData)
	if err != nil {
		t.Fatalf("parseTOML failed: %v", err)
	}
	if cfg.LLM.APIKey != "direct-from-toml" {
		t.Errorf("APIKey = %q, want direct-from-toml", cfg.LLM.APIKey)
	}
	if got := cfg.ResolveAPIKey(); got != "direct-from-toml" {
		t.Errorf("ResolveAPIKey = %q, want direct-from-toml", got)
	}

	// Empty api_key in TOML falls back to api_key_env.
	tomlFallback := `
[llm]
provider = "gemini"
api_key = ""
api_key_env = "TEST_NAY_FALLBACK_KEY"
`
	cfg2, err := parseTOML(tomlFallback)
	if err != nil {
		t.Fatalf("parseTOML fallback failed: %v", err)
	}
	if got := cfg2.ResolveAPIKey(); got != "from-env" {
		t.Errorf("ResolveAPIKey fallback = %q, want from-env", got)
	}
}

func TestXDGHelpers(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/custom-cfg")
	t.Setenv("XDG_CACHE_HOME", "/tmp/custom-cache")

	if got := ConfigPath(); got != "/tmp/custom-cfg/nay/config.toml" {
		t.Errorf("ConfigPath = %q", got)
	}
	if got := CacheDir(); got != "/tmp/custom-cache/nay" {
		t.Errorf("CacheDir = %q", got)
	}
	if got := ReposDir(); got != "/tmp/custom-cache/nay/repos" {
		t.Errorf("ReposDir = %q", got)
	}
	if got := AuditCachePath(); got != "/tmp/custom-cache/nay/audits.json" {
		t.Errorf("AuditCachePath = %q", got)
	}

	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	if !strings.HasSuffix(ConfigPath(), filepath.Join(".config", "nay", "config.toml")) {
		t.Errorf("fallback ConfigPath = %q", ConfigPath())
	}
	if !strings.HasSuffix(AuditCachePath(), filepath.Join(".cache", "nay", "audits.json")) {
		t.Errorf("fallback AuditCachePath = %q", AuditCachePath())
	}
}
