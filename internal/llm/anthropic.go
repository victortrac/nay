package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	defaultAnthropicBaseURL  = "https://api.anthropic.com"
	anthropicAPIVersion      = "2023-06-01"
	anthropicDefaultMaxToken = 4096
)

// AnthropicClient implements Client for the native Anthropic Messages API.
type AnthropicClient struct {
	baseURL    string
	model      string
	apiKey     string
	httpClient *http.Client
}

// NewAnthropicClient creates a new Anthropic Messages API client from cfg.
func NewAnthropicClient(cfg ProviderConfig) (*AnthropicClient, error) {
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		return nil, errors.New("llm/anthropic: model is required")
	}
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		return nil, errors.New("llm/anthropic: api key is required")
	}

	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = defaultAnthropicBaseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/v1")

	return &AnthropicClient{
		baseURL:    baseURL,
		model:      model,
		apiKey:     apiKey,
		httpClient: newHTTPClient(cfg.TimeoutSeconds),
	}, nil
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicMessagesRequest struct {
	Model       string             `json:"model"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature"`
	System      string             `json:"system"`
	Messages    []anthropicMessage `json:"messages"`
}

type anthropicMessagesResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Audit sends the AUR package audit request to Anthropic's /v1/messages endpoint.
func (c *AnthropicClient) Audit(ctx context.Context, req AuditRequest) (*AuditResponse, error) {
	payload := anthropicMessagesRequest{
		Model:       c.model,
		MaxTokens:   anthropicDefaultMaxToken,
		Temperature: 0,
		System:      BuildSystemPrompt(),
		Messages: []anthropicMessage{
			{Role: "user", Content: BuildUserPrompt(req)},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("llm/anthropic: marshal request: %w", err)
	}

	endpoint := c.baseURL + "/v1/messages"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("llm/anthropic: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicAPIVersion)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm/anthropic: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("llm/anthropic: API returned HTTP %d: %s", resp.StatusCode, readErrorBody(resp.Body))
	}

	var msgResp anthropicMessagesResponse
	if err := json.NewDecoder(resp.Body).Decode(&msgResp); err != nil {
		return nil, fmt.Errorf("llm/anthropic: decode response: %w", err)
	}
	if msgResp.Error != nil && msgResp.Error.Message != "" {
		return nil, fmt.Errorf("llm/anthropic: API error: %s", msgResp.Error.Message)
	}

	var text strings.Builder
	for _, block := range msgResp.Content {
		if block.Type == "text" {
			text.WriteString(block.Text)
		}
	}
	if text.Len() == 0 {
		return nil, errors.New("llm/anthropic: response contained no text content")
	}

	return ParseAuditResponse(text.String())
}

// Ping verifies connectivity and authentication against Anthropic's /v1/models endpoint.
func (c *AnthropicClient) Ping(ctx context.Context) error {
	endpoint := c.baseURL + "/v1/models"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("llm/anthropic: build ping request: %w", err)
	}
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicAPIVersion)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("llm/anthropic: ping failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("llm/anthropic: ping returned HTTP %d: %s", resp.StatusCode, readErrorBody(resp.Body))
	}
	return nil
}
