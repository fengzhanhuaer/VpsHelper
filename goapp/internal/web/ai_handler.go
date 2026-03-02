package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"vpshelper-go/internal/store"
)

// AIResponse represents the response from Google AI API
type AIResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
		TotalTokenCount      int `json:"totalTokenCount"`
	} `json:"usageMetadata"`
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// GeminiModelsResponse represents the response from Google AI models list API
type GeminiModelsResponse struct {
	Models []struct {
		Name                       string   `json:"name"`
		DisplayName                string   `json:"displayName"`
		InputTokenLimit            int      `json:"inputTokenLimit"`
		OutputTokenLimit           int      `json:"outputTokenLimit"`
		SupportedGenerationMethods []string `json:"supportedGenerationMethods"`
	} `json:"models"`
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// ChatRequest represents a chat request from frontend
type ChatRequest struct {
	APIKey       string `json:"api_key"`
	Model        string `json:"model"`
	Message      string `json:"message"`
	SystemPrompt string `json:"system_prompt"`
}

// TokenUsage holds token count info from a single API call
type TokenUsage struct {
	PromptTokens    int `json:"prompt_tokens"`
	ResponseTokens  int `json:"response_tokens"`
	TotalTokens     int `json:"total_tokens"`
}

// ChatResponse represents the response to send to frontend
type ChatResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Usage   *TokenUsage `json:"usage,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// aiAssistant handles the AI assistant page
func (h *Handler) aiAssistant(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	settings, _ := store.GetSettings(h.dbConn, []string{"ai_api_key", "ai_model", "ai_system_prompt"})

	c.HTML(http.StatusOK, "ai_assistant.html", gin.H{
		"Title":          "AI 助手",
		"Username":       username,
		"SavedAPIKey":    settings["ai_api_key"],
		"SavedModel":     settings["ai_model"],
		"SavedSysPrompt": settings["ai_system_prompt"],
	})
}

// aiSaveSettings saves AI configuration (API key, model, system prompt) to the database
func (h *Handler) aiSaveSettings(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Unauthorized"})
		return
	}

	var req struct {
		APIKey       string `json:"api_key"`
		Model        string `json:"model"`
		SystemPrompt string `json:"system_prompt"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request"})
		return
	}

	_ = store.SetSetting(h.dbConn, "ai_api_key", req.APIKey)
	_ = store.SetSetting(h.dbConn, "ai_model", req.Model)
	_ = store.SetSetting(h.dbConn, "ai_system_prompt", req.SystemPrompt)

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// aiChat handles the chat API call
func (h *Handler) aiChat(c *gin.Context) {
	var req ChatRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ChatResponse{
			Success: false,
			Error:   "Invalid request format",
		})
		return
	}

	// If no API key in request, fall back to saved key in DB
	if req.APIKey == "" {
		settings, _ := store.GetSettings(h.dbConn, []string{"ai_api_key"})
		req.APIKey = settings["ai_api_key"]
	}

	if req.APIKey == "" {
		c.JSON(http.StatusBadRequest, ChatResponse{
			Success: false,
			Error:   "API Key is required",
		})
		return
	}

	if req.Model == "" {
		req.Model = "gemini-2.0-flash"
	}

	if req.Message == "" {
		c.JSON(http.StatusBadRequest, ChatResponse{
			Success: false,
			Error:   "Message is required",
		})
		return
	}

	// Call Google AI API
	response, usage, err := callGoogleAI(req.APIKey, req.Model, req.Message, req.SystemPrompt)
	if err != nil {
		c.JSON(http.StatusOK, ChatResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, ChatResponse{
		Success: true,
		Message: response,
		Usage:   usage,
	})
}

// callGoogleAI calls the Google Generative AI API
func callGoogleAI(apiKey, model, message, systemPrompt string) (string, *TokenUsage, error) {
	// Build the request URL
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey)

	// Build the request body
	requestBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": message},
				},
			},
		},
	}

	// Add system prompt if provided
	if systemPrompt != "" {
		requestBody["systemInstruction"] = map[string]interface{}{
			"parts": []map[string]string{
				{"text": systemPrompt},
			},
		}
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var aiResp AIResponse
	err = json.Unmarshal(body, &aiResp)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for API errors
	if aiResp.Error.Code != 0 {
		return "", nil, fmt.Errorf("API error: %s", aiResp.Error.Message)
	}

	// Extract text from response
	if len(aiResp.Candidates) == 0 {
		return "", nil, fmt.Errorf("no response from AI")
	}

	if len(aiResp.Candidates[0].Content.Parts) == 0 {
		return "", nil, fmt.Errorf("no text in response")
	}

	usage := &TokenUsage{
		PromptTokens:   aiResp.UsageMetadata.PromptTokenCount,
		ResponseTokens: aiResp.UsageMetadata.CandidatesTokenCount,
		TotalTokens:    aiResp.UsageMetadata.TotalTokenCount,
	}

	return strings.TrimSpace(aiResp.Candidates[0].Content.Parts[0].Text), usage, nil
}

// getAvailableModels fetches the real model list from Gemini API.
// Uses ?api_key=xxx query param, or falls back to the key saved in the database.
// Returns a built-in default list when no key is available.
func (h *Handler) getAvailableModels(c *gin.Context) {
	apiKey := strings.TrimSpace(c.Query("api_key"))
	if apiKey == "" {
		settings, _ := store.GetSettings(h.dbConn, []string{"ai_api_key"})
		apiKey = settings["ai_api_key"]
	}

	type ModelInfo struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		InputTokenLimit  int    `json:"input_token_limit"`
		OutputTokenLimit int    `json:"output_token_limit"`
	}

	if apiKey == "" {
		// No key available – return built-in defaults
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"models": []ModelInfo{
				{ID: "gemini-2.0-flash", Name: "Gemini 2.0 Flash"},
				{ID: "gemini-2.0-flash-lite", Name: "Gemini 2.0 Flash Lite"},
				{ID: "gemini-1.5-pro", Name: "Gemini 1.5 Pro"},
				{ID: "gemini-1.5-flash", Name: "Gemini 1.5 Flash"},
			},
		})
		return
	}

	listURL := "https://generativelanguage.googleapis.com/v1beta/models?key=" + apiKey
	resp, err := http.Get(listURL) //nolint:noctx
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var modelsResp GeminiModelsResponse
	if err := json.Unmarshal(body, &modelsResp); err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": "Failed to parse models response"})
		return
	}

	if modelsResp.Error.Code != 0 {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": modelsResp.Error.Message})
		return
	}

	var models []ModelInfo
	for _, m := range modelsResp.Models {
		for _, method := range m.SupportedGenerationMethods {
			if method == "generateContent" {
				id := strings.TrimPrefix(m.Name, "models/")
				name := m.DisplayName
				if name == "" {
					name = id
				}
				models = append(models, ModelInfo{
					ID:               id,
					Name:             name,
					InputTokenLimit:  m.InputTokenLimit,
					OutputTokenLimit: m.OutputTokenLimit,
				})
				break
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "models": models})
}
