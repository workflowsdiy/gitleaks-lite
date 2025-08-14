package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"gitleaks-lite/internal/config"
	"gitleaks-lite/internal/genai"
	"gitleaks-lite/internal/scanner"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gitleaks-lite",
	Short: "A lightweight secret scanner for git repositories.",
}

var scanCmd = &cobra.Command{
	Use:   "git [path]",
	Short: "Scan a git repository",
	Args:  cobra.ExactArgs(1),
	Run:   runScan,
}

var (
	jsonOutput bool
)

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output findings in JSON format")
	rootCmd.AddCommand(scanCmd)
}

func Execute() error {
	return rootCmd.Execute()
}

func runScan(cmd *cobra.Command, args []string) {
	repoPath := args[0]
	useGenAI := os.Getenv("GEMINI_API_KEY") != ""

	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	var aiValidator *genai.Validator
	if useGenAI {
		log.Info().Msg("GEMINI_API_KEY found, enabling GenAI validation.")
		aiValidator, err = genai.NewValidator(context.Background())
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to initialize Gemini Validator")
		}
	}

	appScanner := scanner.New(cfg)
	var potentialFindings []scanner.Finding

	// Execute git log command
	gitCmd := exec.Command("git", "-C", repoPath, "log", "-p", "-U0", "--full-history", "--all")
	stdout, err := gitCmd.StdoutPipe()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get stdout pipe from git log")
	}

	if err := gitCmd.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start git log command")
	}

	files, err := gitdiff.Parse(stdout)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse git diff")
	}

	log.Info().Msgf("Scanning repository at %s...", repoPath)

	for file := range files {
		findings := appScanner.Scan(file)
		if len(findings) > 0 {
			potentialFindings = append(potentialFindings, findings...)
		}
	}

	if err := gitCmd.Wait(); err != nil {
		log.Warn().Err(err).Msg("Git log command finished with error")
	}

	finalFindings := processFindings(potentialFindings, aiValidator)

	printResults(finalFindings)
}

func processFindings(findings []scanner.Finding, validator *genai.Validator) []scanner.Finding {
	if validator == nil {
		return findings // No AI validation needed
	}

	log.Info().Msgf("Validating %d potential findings with Gemini...", len(findings))

	var validatedFindings []scanner.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, f := range findings {
		wg.Add(1)
		go func(finding scanner.Finding) {
			defer wg.Done()
			result, err := validator.Validate(finding.Secret, finding.CodeContext)
			if err != nil {
				log.Warn().Err(err).Msgf("Failed to validate finding in %s", finding.File)
				// Conservatively include the finding if validation fails
				mu.Lock()
				validatedFindings = append(validatedFindings, finding)
				mu.Unlock()
				return
			}

			if result.IsSecret {
				log.Debug().Msgf("Gemini validation CONFIRMED secret for rule '%s' in %s. Reason: %s", finding.RuleID, finding.File, result.Reason)
				mu.Lock()
				validatedFindings = append(validatedFindings, finding)
				mu.Unlock()
			} else {
				log.Debug().Msgf("Gemini validation REJECTED secret for rule '%s' in %s. Reason: %s", finding.RuleID, finding.File, result.Reason)
			}
		}(f)
	}

	wg.Wait()
	return validatedFindings
}

func printResults(findings []scanner.Finding) {
	if len(findings) == 0 {
		log.Info().Msg("✅ No secrets found.")
		return
	}

	log.Warn().Msgf("🚨 Found %d high-confidence secrets! 🚨", len(findings))

	if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(findings); err != nil {
			log.Fatal().Err(err).Msg("Failed to encode findings to JSON")
		}
	} else {
		for _, f := range findings {
			fmt.Println(strings.Repeat("-", 50))
			fmt.Printf("Rule:     %s\n", f.RuleID)
			fmt.Printf("File:     %s\n", f.File)
			fmt.Printf("Line:     %d\n", f.StartLine)
			fmt.Printf("Commit:   %s\n", f.Commit[:12])
			fmt.Printf("Author:   %s\n", f.Author)
			fmt.Printf("Date:     %s\n", f.Date)
			fmt.Printf("Secret:   %s\n", f.Secret)
			fmt.Println(strings.Repeat("-", 50))
		}
	}
	os.Exit(1)
}
