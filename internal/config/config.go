package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config holds the user configuration for nay.
type Config struct {
	Backend         string
	AutoApproveSafe bool
	Concurrency     int
	LLM             LLMConfig
}

// LLMConfig holds the LLM provider configuration.
type LLMConfig struct {
	Provider       string
	Model          string
	BaseURL        string
	APIKey         string
	APIKeyEnv      string
	TimeoutSeconds int
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Backend:         "yay",
		AutoApproveSafe: false,
		Concurrency:     4,
		LLM: LLMConfig{
			Provider:       "openai-compatible",
			Model:          "gpt-4.1-mini",
			BaseURL:        "",
			APIKeyEnv:      "OPENAI_API_KEY",
			TimeoutSeconds: 60,
		},
	}
}

// DefaultConfigTOML returns the default configuration file content in TOML format.
func DefaultConfigTOML() string {
	return `# AUR helper backend: "yay" or "paru"
backend = "yay"

# Approval behavior:
#   false (default) - always display the verdict table and ask before installing
#   true            - auto-proceed if every package is SAFE; still prompt on WARN/DANGEROUS
auto_approve_safe = false

# Maximum number of concurrent LLM audits during multi-package installs/upgrades
concurrency = 4

[llm]
# Provider: "openai-compatible" | "gemini" | "anthropic"
provider = "openai-compatible"
model = "gpt-4.1-mini"

# Optional custom base URL (e.g., local Ollama, llama.cpp, or OpenRouter)
# base_url = "http://localhost:11434/v1"

# Name of the environment variable holding your API key
api_key_env = "OPENAI_API_KEY"

# Optional direct API key (takes precedence over api_key_env; chmod 600 this file if used)
# api_key = ""

# Request timeout in seconds
timeout_seconds = 60

# Example: Google Gemini
# provider = "gemini"
# model = "gemini-2.5-flash" # or "gemini-2.5-pro", "gemini-4-hydrogen"
# api_key_env = "GEMINI_API_KEY"
`
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return os.Getenv("HOME")
}

// ConfigPath returns the XDG-compliant path to nay's config.toml.
func ConfigPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(homeDir(), ".config")
	}
	return filepath.Join(base, "nay", "config.toml")
}

// CacheDir returns the XDG-compliant cache directory for nay.
func CacheDir() string {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		base = filepath.Join(homeDir(), ".cache")
	}
	return filepath.Join(base, "nay")
}

// ReposDir returns the directory where cloned AUR git repos are stored.
func ReposDir() string {
	return filepath.Join(CacheDir(), "repos")
}

// AuditCachePath returns the path to the JSON audit cache file.
func AuditCachePath() string {
	return filepath.Join(CacheDir(), "audits.json")
}

// Load reads and parses a TOML config file from path.
// If path is empty, ConfigPath() is used.
// If the file does not exist, DefaultConfig() is returned with no error.
func Load(path string) (*Config, error) {
	if path == "" {
		path = ConfigPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	return parseTOML(string(data))
}

// WriteDefault writes DefaultConfigTOML() to path (or ConfigPath() if empty).
// If force is false and the file already exists, an error wrapping os.ErrExist is returned.
func WriteDefault(path string, force bool) error {
	if path == "" {
		path = ConfigPath()
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("config file %q already exists (use --force to overwrite): %w", path, os.ErrExist)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat config %q: %w", path, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(DefaultConfigTOML()), 0o644); err != nil {
		return fmt.Errorf("write config %q: %w", path, err)
	}
	return nil
}

// ResolveAPIKey returns the configured API key, preferring a direct LLM.APIKey
// value when non-empty and otherwise falling back to the environment variable
// named by LLM.APIKeyEnv.
func (c *Config) ResolveAPIKey() string {
	if c == nil {
		return ""
	}
	if key := strings.TrimSpace(c.LLM.APIKey); key != "" {
		return key
	}
	if c.LLM.APIKeyEnv == "" {
		return ""
	}
	return os.Getenv(c.LLM.APIKeyEnv)
}

func defaultAPIKeyEnvForProvider(provider string) string {
	switch provider {
	case "gemini":
		return "GEMINI_API_KEY"
	case "anthropic":
		return "ANTHROPIC_API_KEY"
	default:
		return "OPENAI_API_KEY"
	}
}

func parseTOML(content string) (*Config, error) {
	cfg := DefaultConfig()
	section := ""
	apiKeyEnvExplicit := false
	providerExplicit := false

	// Strip optional UTF-8 BOM.
	content = strings.TrimPrefix(content, "\xef\xbb\xbf")

	lines := strings.Split(content, "\n")
	for i, rawLine := range lines {
		lineNum := i + 1
		line := strings.TrimSpace(stripComment(strings.TrimSuffix(rawLine, "\r")))
		if line == "" {
			continue
		}

		// Section header: [section]
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("line %d: invalid section header %q", lineNum, line)
			}
			sec := strings.TrimSpace(line[1 : len(line)-1])
			if sec == "" {
				return nil, fmt.Errorf("line %d: empty section header", lineNum)
			}
			if sec != "llm" {
				return nil, fmt.Errorf("line %d: unknown section [%s]", lineNum, sec)
			}
			section = sec
			continue
		}

		eqIdx := strings.IndexByte(line, '=')
		if eqIdx < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", lineNum)
		}
		key := strings.TrimSpace(line[:eqIdx])
		val := strings.TrimSpace(line[eqIdx+1:])
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", lineNum)
		}
		if val == "" {
			return nil, fmt.Errorf("line %d: empty value for key %q", lineNum, key)
		}

		switch section {
		case "":
			switch key {
			case "backend":
				s, err := parseTOMLString(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: backend: %w", lineNum, err)
				}
				cfg.Backend = s
			case "auto_approve_safe":
				b, err := parseTOMLBool(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: auto_approve_safe: %w", lineNum, err)
				}
				cfg.AutoApproveSafe = b
			case "concurrency":
				n, err := parseTOMLInt(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: concurrency: %w", lineNum, err)
				}
				cfg.Concurrency = n
			default:
				return nil, fmt.Errorf("line %d: unknown key %q", lineNum, key)
			}
		case "llm":
			switch key {
			case "provider":
				s, err := parseTOMLString(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: llm.provider: %w", lineNum, err)
				}
				cfg.LLM.Provider = s
				providerExplicit = true
			case "model":
				s, err := parseTOMLString(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: llm.model: %w", lineNum, err)
				}
				cfg.LLM.Model = s
			case "base_url":
				s, err := parseTOMLString(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: llm.base_url: %w", lineNum, err)
				}
				cfg.LLM.BaseURL = s
			case "api_key":
				s, err := parseTOMLString(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: llm.api_key: %w", lineNum, err)
				}
				cfg.LLM.APIKey = s
			case "api_key_env":
				s, err := parseTOMLString(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: llm.api_key_env: %w", lineNum, err)
				}
				cfg.LLM.APIKeyEnv = s
				apiKeyEnvExplicit = true
			case "timeout_seconds":
				n, err := parseTOMLInt(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: llm.timeout_seconds: %w", lineNum, err)
				}
				cfg.LLM.TimeoutSeconds = n
			default:
				return nil, fmt.Errorf("line %d: unknown key %q in [llm]", lineNum, key)
			}
		}
	}

	if providerExplicit && !apiKeyEnvExplicit {
		cfg.LLM.APIKeyEnv = defaultAPIKeyEnvForProvider(cfg.LLM.Provider)
	}

	if err := validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func validate(cfg *Config) error {
	switch cfg.Backend {
	case "yay", "paru":
	default:
		return fmt.Errorf("invalid backend %q: must be \"yay\" or \"paru\"", cfg.Backend)
	}
	if cfg.Concurrency < 1 {
		return fmt.Errorf("invalid concurrency %d: must be >= 1", cfg.Concurrency)
	}
	switch cfg.LLM.Provider {
	case "openai-compatible", "gemini", "anthropic":
	default:
		return fmt.Errorf("invalid llm.provider %q: must be \"openai-compatible\", \"gemini\", or \"anthropic\"", cfg.LLM.Provider)
	}
	if cfg.LLM.TimeoutSeconds < 0 {
		return fmt.Errorf("invalid llm.timeout_seconds %d: must be >= 0", cfg.LLM.TimeoutSeconds)
	}
	return nil
}

// stripComment removes a '#' comment outside of single- or double-quoted strings.
func stripComment(line string) string {
	inDouble := false
	inSingle := false
	escaped := false

	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			escaped = false
			continue
		}
		if inDouble {
			if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		switch ch {
		case '"':
			inDouble = true
		case '\'':
			inSingle = true
		case '#':
			return line[:i]
		}
	}
	return line
}

func parseTOMLString(val string) (string, error) {
	if len(val) < 2 {
		return "", fmt.Errorf("expected quoted string, got %q", val)
	}
	if val[0] == '"' && val[len(val)-1] == '"' {
		var b strings.Builder
		inner := val[1 : len(val)-1]
		for i := 0; i < len(inner); i++ {
			if inner[i] != '\\' {
				b.WriteByte(inner[i])
				continue
			}
			i++
			if i >= len(inner) {
				return "", fmt.Errorf("unterminated escape sequence in %q", val)
			}
			switch inner[i] {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			default:
				return "", fmt.Errorf("unsupported escape sequence \\%c", inner[i])
			}
		}
		return b.String(), nil
	}
	if val[0] == '\'' && val[len(val)-1] == '\'' {
		return val[1 : len(val)-1], nil
	}
	return "", fmt.Errorf("expected quoted string, got %q", val)
}

func parseTOMLBool(val string) (bool, error) {
	switch val {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("expected true or false, got %q", val)
	}
}

func parseTOMLInt(val string) (int, error) {
	clean := strings.ReplaceAll(val, "_", "")
	n, err := strconv.Atoi(clean)
	if err != nil {
		return 0, fmt.Errorf("expected integer, got %q", val)
	}
	return n, nil
}
