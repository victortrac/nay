package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const defaultGeminiBaseURL = "https://generativelanguage.googleapis.com"

// GeminiClient implements Client for the native Google Gemini REST API.
type GeminiClient struct {
	baseURL    string
	model      string
	apiKey     string
	httpClient *http.Client
}

// NewGeminiClient creates a new Google Gemini REST API client from cfg.
func NewGeminiClient(cfg ProviderConfig) (*GeminiClient, error) {
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		return nil, errors.New("llm/gemini: model is required")
	}
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		return nil, errors.New("llm/gemini: api key is required")
	}

	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = defaultGeminiBaseURL
	}
	// Strip any trailing /v1beta so endpoint construction is consistent.
	baseURL = strings.TrimSuffix(baseURL, "/v1beta")

	return &GeminiClient{
		baseURL:    baseURL,
		model:      model,
		apiKey:     apiKey,
		httpClient: newHTTPClient(cfg.TimeoutSeconds),
	}, nil
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiGenerationConfig struct {
	Temperature      float64 `json:"temperature"`
	ResponseMimeType string  `json:"responseMimeType,omitempty"`
}

type geminiGenerateRequest struct {
	SystemInstruction *geminiContent          `json:"system_instruction,omitempty"`
	Contents          []geminiContent         `json:"contents"`
	GenerationConfig  *geminiGenerationConfig `json:"generationConfig,omitempty"`
}

type geminiGenerateResponse struct {
	Candidates []struct {
		Content      geminiContent `json:"content"`
		FinishReason string        `json:"finishReason"`
	} `json:"candidates"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error,omitempty"`
}

// Audit sends the AUR package audit request to Gemini's generateContent endpoint.
func (c *GeminiClient) Audit(ctx context.Context, req AuditRequest) (*AuditResponse, error) {
	payload := geminiGenerateRequest{
		SystemInstruction: &geminiContent{
			Parts: []geminiPart{{Text: BuildSystemPrompt()}},
		},
		Contents: []geminiContent{
			{
				Role:  "user",
				Parts: []geminiPart{{Text: BuildUserPrompt(req)}},
			},
		},
		GenerationConfig: &geminiGenerationConfig{
			Temperature:      0,
			ResponseMimeType: "application/json",
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("llm/gemini: marshal request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1beta/models/%s:generateContent", c.baseURL, url.PathEscape(c.model))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("llm/gemini: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-goog-api-key", c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm/gemini: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("llm/gemini: API returned HTTP %d: %s", resp.StatusCode, readErrorBody(resp.Body))
	}

	var genResp geminiGenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&genResp); err != nil {
		return nil, fmt.Errorf("llm/gemini: decode response: %w", err)
	}
	if genResp.Error != nil && genResp.Error.Message != "" {
		return nil, fmt.Errorf("llm/gemini: API error: %s", genResp.Error.Message)
	}
	if len(genResp.Candidates) == 0 {
		return nil, errors.New("llm/gemini: response contained no candidates")
	}

	var text strings.Builder
	for _, part := range genResp.Candidates[0].Content.Parts {
		text.WriteString(part.Text)
	}

	return ParseAuditResponse(text.String())
}

// Ping verifies connectivity, API key validity, and model availability.
func (c *GeminiClient) Ping(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/v1beta/models/%s", c.baseURL, url.PathEscape(c.model))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("llm/gemini: build ping request: %w", err)
	}
	httpReq.Header.Set("x-goog-api-key", c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("llm/gemini: ping failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("llm/gemini: ping returned HTTP %d: %s", resp.StatusCode, readErrorBody(resp.Body))
	}
	return nil
}
