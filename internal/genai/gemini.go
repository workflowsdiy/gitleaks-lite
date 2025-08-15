package genai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/generative-ai-go/genai"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/option"
)

type ValidationResult struct {
	IsSecret   bool   `json:"is_secret"`
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
}

type Validator struct {
	client *genai.GenerativeModel
}

func NewValidator(ctx context.Context) (*Validator, error) {
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("GEMINI_API_KEY environment variable not set")
	}

	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	model := client.GenerativeModel("gemini-2.5-flash")
	model.SetTemperature(0.0)
	return &Validator{client: model}, nil
}

func cleanGeminiResponse(raw string) string {
	if strings.HasPrefix(raw, "```json") {
		raw = strings.TrimPrefix(raw, "```json")
		raw = strings.TrimSuffix(raw, "```")
	}
	return strings.TrimSpace(raw)
}

func (v *Validator) Validate(secret, codeContext string) (*ValidationResult, error) {
	prompt := fmt.Sprintf(`
	You are a security expert specializing in secret detection. Your primary goal is to prevent false positives while being conservative.
	A regular expression has flagged the string "%s" as a potential leaked secret in the following code snippet:

	--- CODE CONTEXT ---
	%s
	--------------------

	Your task is to analyze this and determine if it is a real, active secret or a false positive.
	False positives are things like test data, placeholder values (e.g., "YOUR_API_KEY_HERE"), example keys in documentation, or commented-out code.
	
    **If there is any ambiguity, err on the side of caution and classify it as a secret.**

	Respond ONLY with a valid JSON object in the following format:
	{"is_secret": boolean, "confidence": "High/Medium/Low", "reason": "A brief justification for your decision."}
	`, secret, codeContext)

	ctx := context.Background()
	resp, err := v.client.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return nil, fmt.Errorf("failed to generate content from Gemini: %w", err)
	}

	// --- CORRECTED LOGIC TO ACCESS RESPONSE STRUCTURE ---
	// 1. Check if resp.Candidates slice is populated.
	if len(resp.Candidates) == 0 {
		return nil, fmt.Errorf("received an empty response from Gemini API (no candidates)")
	}
	// 2. Access the first candidate.
	candidate := resp.Candidates[0]

	// 3. Check if the candidate's Content field is not nil and Parts slice is not empty.
	if candidate.Content == nil || len(candidate.Content.Parts) == 0 {
		return nil, fmt.Errorf("received an empty response from Gemini API (no content parts found in candidate)")
	}

	// 4. Access the first part from the candidate's content, which should be genai.Text.
	rawJSON, ok := candidate.Content.Parts[0].(genai.Text)
	if !ok {
		return nil, fmt.Errorf("unexpected response format from Gemini API (expected genai.Text part)")
	}
	// --- END CORRECTED LOGIC ---

	cleanedJSON := cleanGeminiResponse(string(rawJSON))

	var result ValidationResult
	if err := json.Unmarshal([]byte(cleanedJSON), &result); err != nil {
		log.Warn().Str("raw_response", string(rawJSON)).Msg("Failed to unmarshal JSON from Gemini, treating as secret.")
		// Fallback: if JSON is malformed, conservatively treat as a secret.
		return &ValidationResult{IsSecret: true, Confidence: "Low", Reason: "Failed to parse AI response."}, nil
	}

	return &result, nil
}

func (v *Validator) Close() {
	// The current SDK does not require explicit closing of the top-level client.
}
