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
	model.SetTemperature(0.0) // We want deterministic results
	return &Validator{client: model}, nil
}

// THIS IS THE NEW HELPER FUNCTION
func cleanGeminiResponse(raw string) string {
	// The LLM often wraps the JSON in a markdown block.
	// We need to remove the ```json ... ``` part.
	if strings.HasPrefix(raw, "```json") {
		raw = strings.TrimPrefix(raw, "```json")
		raw = strings.TrimSuffix(raw, "```")
	}
	// Also trim any leading/trailing whitespace or newlines.
	return strings.TrimSpace(raw)
}

func (v *Validator) Validate(secret, codeContext string) (*ValidationResult, error) {
	prompt := fmt.Sprintf(`
	You are a security expert specializing in secret detection.
	A regular expression has flagged the string "%s" as a potential leaked secret in the following code snippet:

	--- CODE CONTEXT ---
	%s
	--------------------

	Your task is to analyze this and determine if it is a real, active secret or a false positive.
	False positives include test data, placeholder values, example keys, or commented-out code.
	
	Respond ONLY with a valid JSON object in the following format:
	{"is_secret": boolean, "confidence": "High/Medium/Low", "reason": "A brief justification for your decision."}
	`, secret, codeContext)

	ctx := context.Background()
	resp, err := v.client.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return nil, fmt.Errorf("failed to generate content from Gemini: %w", err)
	}

	if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("received an empty response from Gemini API")
	}

	rawJSON, ok := resp.Candidates[0].Content.Parts[0].(genai.Text)
	if !ok {
		return nil, fmt.Errorf("unexpected response format from Gemini API")
	}

	// USE THE CLEANING FUNCTION HERE
	cleanedJSON := cleanGeminiResponse(string(rawJSON))

	var result ValidationResult
	if err := json.Unmarshal([]byte(cleanedJSON), &result); err != nil {
		log.Warn().Str("raw_response", string(rawJSON)).Msg("Failed to unmarshal JSON from Gemini, treating as secret.")
		return &ValidationResult{IsSecret: true, Confidence: "Low", Reason: "Failed to parse AI response."}, nil
	}

	return &result, nil
}

func (v *Validator) Close() {
	// The current SDK does not require explicit closing of the top-level client.
}
