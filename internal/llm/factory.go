package llm

import (
	"fmt"
	"strings"
)

// NewClient constructs a Client for the configured LLM provider.
// Supported providers are "openai-compatible", "gemini", and "anthropic".
func NewClient(cfg ProviderConfig) (Client, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	switch provider {
	case "openai-compatible", "openai":
		return NewOpenAIClient(cfg)
	case "gemini":
		return NewGeminiClient(cfg)
	case "anthropic":
		return NewAnthropicClient(cfg)
	default:
		return nil, fmt.Errorf("llm: unsupported provider %q (supported: openai-compatible, gemini, anthropic)", cfg.Provider)
	}
}
