package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
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

// ChatResponse represents the response to send to frontend
type ChatResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// aiAssistant handles the AI assistant page
func (h *Handler) aiAssistant(c *gin.Context) {
	// Check session
	session := sessions.Default(c)
	username := session.Get("username")
	if username == nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	c.HTML(http.StatusOK, "ai_assistant.html", gin.H{
		"Title":    "AI 助手",
		"Username": username,
	})
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

	// Validate inputs
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
	response, err := callGoogleAI(req.APIKey, req.Model, req.Message, req.SystemPrompt)
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
	})
}

// callGoogleAI calls the Google Generative AI API
func callGoogleAI(apiKey, model, message, systemPrompt string) (string, error) {
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
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var aiResp AIResponse
	err = json.Unmarshal(body, &aiResp)
	if err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for API errors
	if aiResp.Error.Code != 0 {
		return "", fmt.Errorf("API error: %s", aiResp.Error.Message)
	}

	// Extract text from response
	if len(aiResp.Candidates) == 0 {
		return "", fmt.Errorf("no response from AI")
	}

	if len(aiResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("no text in response")
	}

	return strings.TrimSpace(aiResp.Candidates[0].Content.Parts[0].Text), nil
}

// getAvailableModels returns a list of available Google AI models
func (h *Handler) getAvailableModels(c *gin.Context) {
	models := []map[string]string{
		{"id": "gemini-2.0-flash", "name": "Gemini 2.0 Flash (Fastest)"},
		{"id": "gemini-1.5-pro", "name": "Gemini 1.5 Pro (Most Capable)"},
		{"id": "gemini-1.5-flash", "name": "Gemini 1.5 Flash (Balance)"},
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"models":  models,
	})
}
