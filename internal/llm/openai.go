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

const defaultOpenAIBaseURL = "https://api.openai.com/v1"

// OpenAIClient implements Client for OpenAI-compatible Chat Completions APIs
// (OpenAI, Ollama, llama.cpp, OpenRouter, etc.).
type OpenAIClient struct {
	baseURL    string
	model      string
	apiKey     string
	httpClient *http.Client
}

// NewOpenAIClient creates a new OpenAI-compatible client from cfg.
// APIKey is optional to support local servers such as Ollama or llama.cpp.
func NewOpenAIClient(cfg ProviderConfig) (*OpenAIClient, error) {
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		return nil, errors.New("llm/openai: model is required")
	}

	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = defaultOpenAIBaseURL
	}

	return &OpenAIClient{
		baseURL:    baseURL,
		model:      model,
		apiKey:     strings.TrimSpace(cfg.APIKey),
		httpClient: newHTTPClient(cfg.TimeoutSeconds),
	}, nil
}

type openAIChatRequest struct {
	Model       string          `json:"model"`
	Temperature float64         `json:"temperature"`
	Messages    []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// Audit sends the AUR package audit request to the Chat Completions endpoint.
func (c *OpenAIClient) Audit(ctx context.Context, req AuditRequest) (*AuditResponse, error) {
	payload := openAIChatRequest{
		Model:       c.model,
		Temperature: 0,
		Messages: []openAIMessage{
			{Role: "system", Content: BuildSystemPrompt()},
			{Role: "user", Content: BuildUserPrompt(req)},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("llm/openai: marshal request: %w", err)
	}

	endpoint := c.baseURL + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("llm/openai: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm/openai: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("llm/openai: API returned HTTP %d: %s", resp.StatusCode, readErrorBody(resp.Body))
	}

	var chatResp openAIChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return nil, fmt.Errorf("llm/openai: decode response: %w", err)
	}
	if chatResp.Error != nil && chatResp.Error.Message != "" {
		return nil, fmt.Errorf("llm/openai: API error: %s", chatResp.Error.Message)
	}
	if len(chatResp.Choices) == 0 {
		return nil, errors.New("llm/openai: response contained no choices")
	}

	return ParseAuditResponse(chatResp.Choices[0].Message.Content)
}

// Ping verifies connectivity and authentication against the /models endpoint.
func (c *OpenAIClient) Ping(ctx context.Context) error {
	endpoint := c.baseURL + "/models"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("llm/openai: build ping request: %w", err)
	}
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("llm/openai: ping failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("llm/openai: ping returned HTTP %d: %s", resp.StatusCode, readErrorBody(resp.Body))
	}
	return nil
}
