Project Path: data

Source Tree:

```txt
data
├── Dockerfile
├── README.md
├── SECURITY_REVIEW.md
├── cmd
│   └── scan.go
├── code.md
├── entrypoint.sh
├── go.mod
├── go.sum
├── internal
│   ├── config
│   │   ├── config.go
│   │   └── gitleaks.toml
│   ├── genai
│   │   └── gemini.go
│   └── scanner
│       └── scanner.go
├── main.go
├── run_tests.sh
├── scan_all_repos.sh
└── testdata
    ├── expected
    └── repos
        ├── repo-clean
        │   └── README.md
        ├── repo-with-false-positive
        │   └── examples.py
        └── repo-with-secret
            └── config.yml

```

`Dockerfile`:

```
# ---- Build Stage ----
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the statically-linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/gitleaks-lite .

# ---- Final Stage ----
FROM alpine:latest

# Install git, which is the only runtime dependency
RUN apk add --no-cache git

# Copy the binary from the builder stage
COPY --from=builder /app/gitleaks-lite /usr/local/bin/gitleaks-lite

# Copy the entrypoint wrapper script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# Set the entrypoint for the container to our new script
ENTRYPOINT ["entrypoint.sh"]

# The default command can be to show help
CMD ["--help"]
```

`README.md`:

```md
# Gitleaks-Lite

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-audited-blue)](security_summary.md)

A minimalist, containerized CLI tool to rapidly scan Git repositories for high-confidence secrets, with an optional AI-powered validation layer using Google Gemini to eliminate false positives.

## Motivation

Powerful security tools like the original [Gitleaks](https://github.com/gitleaks/gitleaks) are feature-rich and highly configurable, making them ideal for complex security programs. However, for the common use case of a developer wanting a quick, simple scan without configuring rules or wading through false positives, a lighter approach is needed.

**Gitleaks-Lite** is designed for this exact scenario. It adheres to an 80/20 philosophy by focusing exclusively on scanning Git repositories with a curated, embedded ruleset for the most common secret types. It's a "fire and forget" tool that provides immediate, high-confidence results.

## Features

-   **Zero-Configuration:** No `.toml` file needed. The tool comes with a built-in, curated set of high-confidence rules.
-   **High-Speed Regex Scan:** Utilizes a fast, regex-based engine to perform an initial scan of the entire repository history.
-   **AI-Powered Validation (Optional):** Uses the Google Gemini API as a secondary validation pass to analyze the context of potential secrets, dramatically reducing false positives from test files, examples, and placeholders.
-   **Containerized & Secure:** Runs in a self-contained, minimal Docker image with **no host dependencies** other than Docker itself. Go and Git are included in the image. The application runs as a non-root user within the container.
-   **Simple, Actionable Output:** Reports are printed directly to the console in a human-readable format or as JSON for easy CI/CD integration.

## How It Works: A Hybrid Approach

Gitleaks-Lite employs a powerful two-phase scanning process to maximize both speed and accuracy.

```plaintext
Phase 1: High-Speed Regex Scan (Always On)
  - Scans the entire Git history using a fast, embedded ruleset.
  - Generates a list of "potential findings".
  - If AI validation is disabled, this is the final report.

      │
      └─ (If GenAI is enabled) ──>
                                  │

Phase 2: AI Validation with Gemini (Optional)
  - For each potential finding, it sends the secret and its surrounding code context to the Gemini API.
  - Asks the AI to act as a security expert and determine if it's a true secret or a false positive.
  - Discards findings that the AI confidently identifies as false positives.

      │
      └──>

Final Report: High-Confidence Secrets
  - The final output contains only the secrets that are either un-validated
    or have been confirmed by the AI, resulting in a cleaner, more actionable report.
```

## Security and Data Privacy

Your security and privacy are paramount. When you enable the GenAI-Enhanced Scan by providing a `GEMINI_API_KEY`, this tool sends a limited amount of data to the Google Gemini API for validation.

**What is Sent:**
*   The potential secret string (the text flagged by the initial regex scan).
*   A small snippet of the surrounding code (approximately 5 lines) to provide the necessary context for validation.

**What is NOT Sent:**
*   The filename or the full file content.
*   The commit hash, author name, email, or any other Git metadata.
*   The name of your repository or any other identifying project information.

The data sent is used by Google for the sole purpose of returning a validation result and is governed by Google Cloud's [Generative AI data governance policies](https://cloud.google.com/vertex-ai/docs/generative-ai/data-governance).

**If you are working in a high-security environment or are not comfortable with sending code snippets to a third-party API, do not set the `GEMINI_API_KEY` environment variable.** The tool will remain fully functional and secure in its fast, local, regex-only mode.

For a detailed security overview, please see the [Security Summary](security_summary.md).

## Getting Started

### Prerequisites

-   [Docker](https://docs.docker.com/get-docker/) installed and running.
-   A local Git repository you wish to scan.

### Installation

The only installation step is to build the Docker image. From the root of this project, run:

```sh
docker build -t gitleaks-lite .
```

## Usage

### 1. Standard Scan (Regex-Only)

This is the fastest method and performs the scan entirely locally without requiring an API key. To scan a local Git repository, mount it as a volume to the `/scan` directory inside the container.

```sh
# Replace /path/to/your/local/repo with the absolute path to your project
docker run --rm -v "/path/to/your/local/repo:/scan" gitleaks-lite git /scan
```

### 2. GenAI-Enhanced Scan

To enable the secondary validation pass with Google Gemini, you must provide your API key as an environment variable.

**Get your API key:** [Google AI Studio](https://aistudio.google.com/app/apikey)

```sh
docker run --rm -v "/path/to/your/local/repo:/scan" \
  -e GEMINI_API_KEY="YOUR_API_KEY_HERE" \
  gitleaks-lite git /scan
```
*Note: Handle your `GEMINI_API_KEY` as a secret. For CI/CD environments, use your platform's built-in secret management features.*

### 3. Scanning Multiple Repositories

This project includes a helper script, `scan_all_repos.sh`, to scan all Git repositories within a specified directory.

1.  **Configure the script:** Open `scan_all_repos.sh` and adjust the `SCAN_DIRECTORY` and `USE_GEMINI` variables.
2.  **Make it executable:** `chmod +x scan_all_repos.sh`
3.  **Run it:** `./scan_all_repos.sh`

### 4. JSON Output for CI/CD

For machine-readable output, which is useful for scripting and integration with other tools, use the `--json` flag. The tool will exit with code `1` if secrets are found and `0` otherwise.

```sh
docker run --rm -v "/path/to/your/local/repo:/scan" gitleaks-lite git /scan --json
```

### Ignoring Findings

The only supported method for ignoring a specific finding is to add a `gitleaks:allow` comment on the same line as the secret, or in a block comment directly above it, in your source code.

```go
// This secret will be ignored by the scanner
var mySecret = "some_secret_value_here" // gitleaks:allow
```

## Local Development and Testing

This project includes a comprehensive, automated testing suite. The test runner script will lint, format, build the Docker image, and run a series of integration tests against purpose-built test repositories.

To run the full suite:

```sh
# To run all tests, including the AI validation ones
export GEMINI_API_KEY="YOUR_API_KEY_HERE"

# Run the test script
./run_tests.sh
```

If you do not set the `GEMINI_API_KEY`, the script will automatically skip the AI-related tests.

## Contributing

Contributions are welcome! Please ensure that any pull requests adhere to the standard Go formatting and that all tests pass.

1.  **Format your code:** `go fmt ./...`
2.  **Run the test suite:** `./run_tests.sh`

## License

This project is licensed under the MIT License.
```

`SECURITY_REVIEW.md`:

```md
# Security Summary

This document provides a summary of the security posture of the **Gitleaks-Lite** project, including its design principles, data handling practices, and potential risks.

## 1. Core Design and Threat Model

**Gitleaks-Lite** is designed as a command-line utility that runs inside a Docker container. Its primary function is to scan a Git repository (mounted as a volume) for secrets.

The threat model considers the following:

*   **Primary Goal:** To prevent accidental exposure of secrets in Git repositories.
*   **Primary Assets:** The secrets within the code being scanned and the user's `GEMINI_API_KEY`.
*   **Main Threat Actors:**
    1.  Maintainers or users of the tool who might misunderstand its security boundaries.
    2.  Attackers who gain access to the environment where the tool is run (e.g., a CI/CD runner or a developer's machine).

The core security principle is **isolation**. By running inside a container, the tool has no access to the host system beyond the explicitly mounted repository directory.

## 2. Data Handling and Privacy

Data handling practices are critical, especially when an external AI service is used.

### Regex-Only Mode (Default)

*   **Execution:** Entirely local.
*   **Data Sent:** No data ever leaves the container or the machine it is running on.
*   **Security:** This mode is suitable for all environments, including those with strict data residency and privacy requirements.

### GenAI-Enhanced Mode (Optional)

This mode is only activated when a `GEMINI_API_KEY` is provided.

*   **What is Sent to Google Gemini API:**
    *   The potential secret string (e.g., `"ghp_..."`).
    *   A small code snippet (~5 lines) surrounding the potential secret for context.

*   **What is NOT Sent:**
    *   Git metadata (commit hash, author, email, commit message).
    *   The filename or the full file content.
    *   The repository's name or origin.

*   **Data Governance:** The data sent to the Gemini API is governed by Google Cloud's [Generative AI data governance policies](https://cloud.google.com/vertex-ai/docs/generative-ai/data-governance). This data is used solely for the validation request and is not used for training models.

**Recommendation:** Users in high-security environments should use the default regex-only mode if sending code snippets to a third-party API is against their security policy.

## 3. Security Hardening Measures

Several measures have been implemented to secure the application and its environment.

### Container Security

*   **Multi-Stage Builds:** The `Dockerfile` uses a multi-stage build to create a minimal final image, reducing the attack surface by excluding the Go toolchain and build-time dependencies.
*   **Minimal Dependencies:** The final image is based on `alpine:latest` and only includes `git`, which is the sole runtime dependency. This minimizes the number of packages that could contain vulnerabilities.
*   **Non-Root Execution (Recommended):** The tool is designed to be run as a non-root user inside the container to limit the impact of a potential container escape vulnerability. Users can enforce this by adding `USER gitleaks` to the Dockerfile or using `docker run --user`.

### Code Security

*   **No `unsafe` Go:** The project avoids using the `unsafe` package in Go, preventing low-level memory corruption bugs.
*   **Dependency Management:** Dependencies are managed via `go.mod` and `go.sum`, ensuring reproducible builds. Regular dependency scanning is recommended to identify and update vulnerable packages.
*   **Secure API Usage:** The client for the Gemini API is initialized using the official Google Go SDK, which handles secure TLS communication.
*   **Concurrency Safety:** When performing AI validation, Go channels and WaitGroups are used to manage concurrent operations safely, preventing race conditions.

## 4. Known Risks and Mitigations

*   **Compromised `GEMINI_API_KEY`:**
    *   **Risk:** If the `GEMINI_API_KEY` is leaked, an attacker could use it to make requests to the Gemini API at the owner's expense.
    *   **Mitigation:** The key is only ever read from an environment variable. Users are instructed to handle this key as a secret and use a secrets manager in CI/CD environments. It is never stored or logged by the application.

*   **Malicious Repository:**
    *   **Risk:** A repository with maliciously crafted file content could theoretically target a vulnerability in the `gitdiff` parser or the Go standard library.
    *   **Mitigation:** The application runs in a container with limited privileges, minimizing the potential impact. The Go runtime also provides memory safety, reducing the risk of buffer overflows.

*   **False Negatives:**
    *   **Risk:** The tool might fail to detect a real secret.
    *   **Mitigation:** This is an inherent risk in any secret scanner. The regex rules are curated to be effective, but they cannot be exhaustive. The AI validation layer is tuned to be conservative, erring on the side of caution. Users should not rely on this tool as their only security measure.

This summary is intended to provide transparency into the security of Gitleaks-Lite. Users are encouraged to review the source code and use the tool in accordance with their own security policies.
```

`cmd/scan.go`:

```go
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

```

`code.md`:

```md
Project Path: data

Source Tree:

```txt
data
├── Dockerfile
├── README.md
├── cmd
│   └── scan.go
├── entrypoint.sh
├── go.mod
├── go.sum
├── internal
│   ├── config
│   │   ├── config.go
│   │   └── gitleaks.toml
│   ├── genai
│   │   └── gemini.go
│   └── scanner
│       └── scanner.go
├── main.go
├── run_tests.sh
├── scan_all_repos.sh
└── testdata
    ├── expected
    └── repos
        ├── repo-clean
        │   └── README.md
        ├── repo-with-false-positive
        │   └── examples.py
        └── repo-with-secret
            └── config.yml

```

`Dockerfile`:

```
# ---- Build Stage ----
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the statically-linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/gitleaks-lite .

# ---- Final Stage ----
FROM alpine:latest

# Install git, which is the only runtime dependency
RUN apk add --no-cache git

# Copy the binary from the builder stage
COPY --from=builder /app/gitleaks-lite /usr/local/bin/gitleaks-lite

# Copy the entrypoint wrapper script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# Set the entrypoint for the container to our new script
ENTRYPOINT ["entrypoint.sh"]

# The default command can be to show help
CMD ["--help"]
```

`README.md`:

```md
Of course. Here is a complete, updated `README.md` file that incorporates the security and privacy recommendations, ready for your public repository.

***

# Gitleaks-Lite

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A minimalist, zero-configuration CLI tool to rapidly scan Git repositories for high-confidence secrets, with an optional AI-powered validation layer using Google Gemini.

## Motivation

Powerful security tools like the original [Gitleaks](https://github.com/gitleaks/gitleaks) are feature-rich and highly configurable, making them ideal for complex security programs. However, for the common use case of a developer wanting a quick, simple scan without configuring rules or wading through false positives, a lighter approach is needed.

**Gitleaks-Lite** is designed to solve this problem. It adheres to an 80/20 philosophy by focusing exclusively on scanning Git repositories with a curated, embedded ruleset for the most common secret types. It's built to be a "fire and forget" tool that provides immediate, high-confidence results.

## Features

-   **Zero-Configuration:** No `.toml` file needed. The tool comes with a built-in, curated set of high-confidence rules.
-   **High-Speed Regex Scan:** Utilizes a fast, regex-based engine to perform the initial scan of the entire repository history.
-   **AI-Powered Validation:** Optionally uses the Google Gemini API as a secondary validation pass to analyze the context of potential secrets, dramatically reducing false positives from test files, examples, and placeholders.
-   **Containerized & Portable:** Runs in a self-contained Docker image with **no host dependencies** other than Docker itself. Go and Git are included in the image.
-   **Simple, Actionable Output:** Reports are printed directly to the console in a human-readable format or as JSON for easy integration.

## How It Works: A Hybrid Approach

Gitleaks-Lite employs a powerful two-phase scanning process to maximize both speed and accuracy.

```plaintext
Phase 1: High-Speed Regex Scan (Always On)
  - Scans the entire Git history using a fast, embedded ruleset.
  - Generates a list of "potential findings".
  - If AI validation is disabled, this is the final report.

      │
      └─ (If GenAI is enabled) ──>
                                  │

Phase 2: AI Validation with Gemini (Optional)
  - Sends each potential finding and its surrounding code context to the Gemini API.
  - Asks the AI to act as a security expert and determine if it's a true secret or a false positive.
  - Discards findings that the AI identifies as false positives.

      │
      └──>

Final Report: High-Confidence Secrets
  - The final output contains only the secrets confirmed by the AI,
    resulting in a cleaner, more actionable report.
```

## Privacy and Data Handling

When you enable the GenAI-Enhanced Scan by providing a `GEMINI_API_KEY`, this tool sends data to the Google Gemini API for validation.

**What is Sent:**
*   The potential secret (the string flagged by the initial regex scan).
*   A small snippet of the surrounding code (approximately 5 lines) to provide the necessary context for validation.

**What is NOT Sent:**
*   The filename or the full file content.
*   The commit hash, author name, or any other Git metadata.

The data sent is used by Google for the sole purpose of returning a validation result and is governed by Google Cloud's [Generative AI data governance policies](https://cloud.google.com/vertex-ai/docs/generative-ai/data-governance).

**If you are working in a high-security environment or are not comfortable with sending code snippets to a third-party API, do not set the `GEMINI_API_KEY` environment variable.** The tool will remain fully functional in its fast, local, regex-only mode.

## Getting Started

### Prerequisites

-   [Docker](https://docs.docker.com/get-docker/) installed and running.
-   A local Git repository to scan.

### Installation

The only installation step is to build the Docker image. From the root of this project, run:

```sh
docker build -t gitleaks-lite .
```

## Usage

### 1. Standard Scan (Regex-Only)

This is the fastest method and does not require an API key. To scan a local Git repository, mount it as a volume to the `/scan` directory inside the container.

```sh
# Replace /path/to/your/local/repo with the absolute path to your project
docker run --rm -v "/path/to/your/local/repo:/scan" gitleaks-lite git /scan
```

### 2. GenAI-Enhanced Scan

To enable the secondary validation pass with Google Gemini, you must provide your API key as an environment variable.

**Get your API key:** [Google AI Studio](https://aistudio.google.com/app/apikey)

```sh
docker run --rm -v "/path/to/your/local/repo:/scan" \
  -e GEMINI_API_KEY="YOUR_API_KEY_HERE" \
  gitleaks-lite git /scan
```

### 3. Scanning Multiple Repositories

This project includes a helper script, `scan_all_repos.sh`, to scan all Git repositories within a specified directory.

1.  **Configure the script:** Open `scan_all_repos.sh` and adjust the `SCAN_DIRECTORY` and `USE_GEMINI` variables.
2.  **Make it executable:** `chmod +x scan_all_repos.sh`
3.  **Run it:** `./scan_all_repos.sh`

### 4. JSON Output

For machine-readable output, which is useful for scripting and integration with other tools, use the `--json` flag.

```sh
docker run --rm -v "/path/to/your/local/repo:/scan" gitleaks-lite git /scan --json
```

### Handling False Positives

The only supported method for ignoring a specific finding is to add a `gitleaks:allow` comment on the same line as the secret in your source code.

```go
// This secret will be ignored by the scanner
var mySecret = "some_secret_value_here" // gitleaks:allow
```

## Testing

This project includes a comprehensive, automated testing suite. The test runner script will lint, format, build the Docker image, and run a series of integration tests against purpose-built test repositories.

To run the full suite:

```sh
# Set your Gemini key to run all tests
export GEMINI_API_KEY="YOUR_API_KEY_HERE"

# Run the test script
./run_tests.sh
```

If you do not set the `GEMINI_API_KEY`, the script will automatically skip the AI-related tests.

## Contributing

Contributions are welcome! Please ensure that any pull requests adhere to the standard Go formatting and that all tests pass.

1.  Format your code: `go fmt ./...`
2.  Run the test suite: `./run_tests.sh`

## License

This project is licensed under the MIT License.
```

`cmd/scan.go`:

```go
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

```

`entrypoint.sh`:

```sh
#!/bin/sh

# This script runs every time the container starts.

# The `git` command expects to run in a directory, but our scanner
# specifies the path. We'll run this from the root. The scanner will
# use the correct path provided in its arguments.
git config --global --add safe.directory /scan

# Now, execute the main gitleaks-lite application, passing along
# all the arguments that were given to the container.
exec gitleaks-lite "$@"

```

`go.mod`:

```mod
module gitleaks-lite

go 1.23

require (
	github.com/BurntSushi/toml v1.4.0
	github.com/gitleaks/go-gitdiff v0.9.1
	github.com/google/generative-ai-go v0.15.0
	github.com/rs/zerolog v1.33.0
	github.com/spf13/cobra v1.8.1
	google.golang.org/api v0.189.0
)

require (
	cloud.google.com/go v0.115.0 // indirect
	cloud.google.com/go/ai v0.8.0 // indirect
	cloud.google.com/go/auth v0.7.2 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.3 // indirect
	cloud.google.com/go/compute/metadata v0.5.0 // indirect
	cloud.google.com/go/longrunning v0.5.9 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/googleapis/gax-go/v2 v2.13.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.51.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.51.0 // indirect
	go.opentelemetry.io/otel v1.26.0 // indirect
	go.opentelemetry.io/otel/metric v1.26.0 // indirect
	go.opentelemetry.io/otel/trace v1.26.0 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/net v0.27.0 // indirect
	golang.org/x/oauth2 v0.21.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240722135656-d784300faade // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240722135656-d784300faade // indirect
	google.golang.org/grpc v1.65.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

```

`go.sum`:

```sum
cloud.google.com/go v0.26.0/go.mod h1:aQUYkXzVsufM+DwF1aE+0xfcU+56JwCaLick0ClmMTw=
cloud.google.com/go v0.115.0 h1:CnFSK6Xo3lDYRoBKEcAtia6VSC837/ZkJuRduSFnr14=
cloud.google.com/go v0.115.0/go.mod h1:8jIM5vVgoAEoiVxQ/O4BFTfHqulPZgs/ufEzMcFMdWU=
cloud.google.com/go/ai v0.8.0 h1:rXUEz8Wp2OlrM8r1bfmpF2+VKqc1VJpafE3HgzRnD/w=
cloud.google.com/go/ai v0.8.0/go.mod h1:t3Dfk4cM61sytiggo2UyGsDVW3RF1qGZaUKDrZFyqkE=
cloud.google.com/go/auth v0.7.2 h1:uiha352VrCDMXg+yoBtaD0tUF4Kv9vrtrWPYXwutnDE=
cloud.google.com/go/auth v0.7.2/go.mod h1:VEc4p5NNxycWQTMQEDQF0bd6aTMb6VgYDXEwiJJQAbs=
cloud.google.com/go/auth/oauth2adapt v0.2.3 h1:MlxF+Pd3OmSudg/b1yZ5lJwoXCEaeedAguodky1PcKI=
cloud.google.com/go/auth/oauth2adapt v0.2.3/go.mod h1:tMQXOfZzFuNuUxOypHlQEXgdfX5cuhwU+ffUuXRJE8I=
cloud.google.com/go/compute/metadata v0.5.0 h1:Zr0eK8JbFv6+Wi4ilXAR8FJ3wyNdpxHKJNPos6LTZOY=
cloud.google.com/go/compute/metadata v0.5.0/go.mod h1:aHnloV2TPI38yx4s9+wAZhHykWvVCfu7hQbF+9CWoiY=
cloud.google.com/go/longrunning v0.5.9 h1:haH9pAuXdPAMqHvzX0zlWQigXT7B0+CL4/2nXXdBo5k=
cloud.google.com/go/longrunning v0.5.9/go.mod h1:HD+0l9/OOW0za6UWdKJtXoFAX/BGg/3Wj8p10NeWF7c=
github.com/BurntSushi/toml v0.3.1/go.mod h1:xHWCNGjB5oqiDr8zfno3MHue2Ht5sIBksp03qcyfWMU=
github.com/BurntSushi/toml v1.4.0 h1:kuoIxZQy2WRRk1pttg9asf+WVv6tWQuBNVmK8+nqPr0=
github.com/BurntSushi/toml v1.4.0/go.mod h1:ukJfTF/6rtPPRCnwkur4qwRxa8vTRFBF0uk2lLoLwho=
github.com/census-instrumentation/opencensus-proto v0.2.1/go.mod h1:f6KPmirojxKA12rnyqOA5BBL4O983OfeGPqjHWSTneU=
github.com/client9/misspell v0.3.4/go.mod h1:qj6jICC3Q7zFZvVWo7KLAzC3yx5G7kyvSDkc90ppPyw=
github.com/cncf/udpa/go v0.0.0-20191209042840-269d4d468f6f/go.mod h1:M8M6+tZqaGXZJjfX53e64911xZQV5JYwmTeXPW+k8Sc=
github.com/coreos/go-systemd/v22 v22.5.0/go.mod h1:Y58oyj3AT4RCenI/lSvhwexgC+NSVTIJ3seZv2GcEnc=
github.com/cpuguy83/go-md2man/v2 v2.0.4/go.mod h1:tgQtvFlXSQOSOSIRvRPT7W67SCa46tRHOmNcaadrF8o=
github.com/davecgh/go-spew v1.1.0/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/davecgh/go-spew v1.1.1 h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=
github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/envoyproxy/go-control-plane v0.9.0/go.mod h1:YTl/9mNaCwkRvm6d1a2C3ymFceY/DCBVvsKhRF0iEA4=
github.com/envoyproxy/go-control-plane v0.9.1-0.20191026205805-5f8ba28d4473/go.mod h1:YTl/9mNaCwkRvm6d1a2C3ymFceY/DCBVvsKhRF0iEA4=
github.com/envoyproxy/go-control-plane v0.9.4/go.mod h1:6rpuAdCZL397s3pYoYcLgu1mIlRU8Am5FuJP05cCM98=
github.com/envoyproxy/protoc-gen-validate v0.1.0/go.mod h1:iSmxcyjqTsJpI2R4NaDN7+kN2VEUnK/pcBlmesArF7c=
github.com/felixge/httpsnoop v1.0.4 h1:NFTV2Zj1bL4mc9sqWACXbQFVBBg2W3GPvqp8/ESS2Wg=
github.com/felixge/httpsnoop v1.0.4/go.mod h1:m8KPJKqk1gH5J9DgRY2ASl2lWCfGKXixSwevea8zH2U=
github.com/gitleaks/go-gitdiff v0.9.1 h1:ni6z6/3i9ODT685OLCTf+s/ERlWUNWQF4x1pvoNICw0=
github.com/gitleaks/go-gitdiff v0.9.1/go.mod h1:pKz0X4YzCKZs30BL+weqBIG7mx0jl4tF1uXV9ZyNvrA=
github.com/go-logr/logr v1.2.2/go.mod h1:jdQByPbusPIv2/zmleS9BjJVeZ6kBagPoEUsqbVz/1A=
github.com/go-logr/logr v1.4.2 h1:6pFjapn8bFcIbiKo3XT4j/BhANplGihG6tvd+8rYgrY=
github.com/go-logr/logr v1.4.2/go.mod h1:9T104GzyrTigFIr8wt5mBrctHMim0Nb2HLGrmQ40KvY=
github.com/go-logr/stdr v1.2.2 h1:hSWxHoqTgW2S2qGc0LTAI563KZ5YKYRhT3MFKZMbjag=
github.com/go-logr/stdr v1.2.2/go.mod h1:mMo/vtBO5dYbehREoey6XUKy/eSumjCCveDpRre4VKE=
github.com/godbus/dbus/v5 v5.0.4/go.mod h1:xhWf0FNVPg57R7Z0UbKHbJfkEywrmjJnf7w5xrFpKfA=
github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b/go.mod h1:SBH7ygxi8pfUlaOkMMuAQtPIUF8ecWP5IEl/CR7VP2Q=
github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e/go.mod h1:cIg4eruTrX1D+g88fzRXU5OdNfaM+9IcxsU14FzY7Hc=
github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da h1:oI5xCqsCo564l8iNU+DwB5epxmsaqB+rhGL0m5jtYqE=
github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da/go.mod h1:cIg4eruTrX1D+g88fzRXU5OdNfaM+9IcxsU14FzY7Hc=
github.com/golang/mock v1.1.1/go.mod h1:oTYuIxOrZwtPieC+H1uAHpcLFnEyAGVDL/k47Jfbm0A=
github.com/golang/protobuf v1.2.0/go.mod h1:6lQm79b+lXiMfvg/cZm0SGofjICqVBUtrP5yJMmIC1U=
github.com/golang/protobuf v1.3.2/go.mod h1:6lQm79b+lXiMfvg/cZm0SGofjICqVBUtrP5yJMmIC1U=
github.com/golang/protobuf v1.4.0-rc.1/go.mod h1:ceaxUfeHdC40wWswd/P6IGgMaK3YpKi5j83Wpe3EHw8=
github.com/golang/protobuf v1.4.0-rc.1.0.20200221234624-67d41d38c208/go.mod h1:xKAWHe0F5eneWXFV3EuXVDTCmh+JuBKY0li0aMyXATA=
github.com/golang/protobuf v1.4.0-rc.2/go.mod h1:LlEzMj4AhA7rCAGe4KMBDvJI+AwstrUpVNzEA03Pprs=
github.com/golang/protobuf v1.4.0-rc.4.0.20200313231945-b860323f09d0/go.mod h1:WU3c8KckQ9AFe+yFwt9sWVRKCVIyN9cPHBJSNnbL67w=
github.com/golang/protobuf v1.4.0/go.mod h1:jodUvKwWbYaEsadDk5Fwe5c77LiNKVO9IDvqG2KuDX0=
github.com/golang/protobuf v1.4.1/go.mod h1:U8fpvMrcmy5pZrNK1lt4xCsGvpyWQ/VVv6QDs8UjoX8=
github.com/golang/protobuf v1.4.3/go.mod h1:oDoupMAO8OvCJWAcko0GGGIgR6R6ocIYbsSw735rRwI=
github.com/golang/protobuf v1.5.4 h1:i7eJL8qZTpSEXOPTxNKhASYpMn+8e5Q6AdndVa1dWek=
github.com/golang/protobuf v1.5.4/go.mod h1:lnTiLA8Wa4RWRcIUkrtSVa5nRhsEGBg48fD6rSs7xps=
github.com/google/generative-ai-go v0.15.0 h1:0PQF6ib/72Sa8SfVkqsyzHqgVZH2MxpIa/krpbGDT7E=
github.com/google/generative-ai-go v0.15.0/go.mod h1:AAucpWZjXsDKhQYWvCYuP6d0yB1kX998pJlOW1rAesw=
github.com/google/go-cmp v0.2.0/go.mod h1:oXzfMopK8JAjlY9xF4vHSVASa0yLyX7SntLO5aqRK0M=
github.com/google/go-cmp v0.3.0/go.mod h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=
github.com/google/go-cmp v0.3.1/go.mod h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=
github.com/google/go-cmp v0.4.0/go.mod h1:v8dTdLbMG2kIc/vJvl+f65V22dbkXbowE6jgT/gNBxE=
github.com/google/go-cmp v0.5.0/go.mod h1:v8dTdLbMG2kIc/vJvl+f65V22dbkXbowE6jgT/gNBxE=
github.com/google/go-cmp v0.5.3/go.mod h1:v8dTdLbMG2kIc/vJvl+f65V22dbkXbowE6jgT/gNBxE=
github.com/google/go-cmp v0.6.0 h1:ofyhxvXcZhMsU5ulbFiLKl/XBFqE1GSq7atu8tAmTRI=
github.com/google/go-cmp v0.6.0/go.mod h1:17dUlkBOakJ0+DkrSSNjCkIjxS6bF9zb3elmeNGIjoY=
github.com/google/s2a-go v0.1.7 h1:60BLSyTrOV4/haCDW4zb1guZItoSq8foHCXrAnjBo/o=
github.com/google/s2a-go v0.1.7/go.mod h1:50CgR4k1jNlWBu4UfS4AcfhVe1r6pdZPygJ3R8F0Qdw=
github.com/google/uuid v1.1.2/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/googleapis/enterprise-certificate-proxy v0.3.2 h1:Vie5ybvEvT75RniqhfFxPRy3Bf7vr3h0cechB90XaQs=
github.com/googleapis/enterprise-certificate-proxy v0.3.2/go.mod h1:VLSiSSBs/ksPL8kq3OBOQ6WRI2QnaFynd1DCjZ62+V0=
github.com/googleapis/gax-go/v2 v2.13.0 h1:yitjD5f7jQHhyDsnhKEBU52NdvvdSeGzlAnDPT0hH1s=
github.com/googleapis/gax-go/v2 v2.13.0/go.mod h1:Z/fvTZXF8/uw7Xu5GuslPw+bplx6SS338j1Is2S+B7A=
github.com/inconshreveable/mousetrap v1.1.0 h1:wN+x4NVGpMsO7ErUn/mUI3vEoE6Jt13X2s0bqwp9tc8=
github.com/inconshreveable/mousetrap v1.1.0/go.mod h1:vpF70FUmC8bwa3OWnCshd2FqLfsEA9PFc4w1p2J65bw=
github.com/mattn/go-colorable v0.1.13 h1:fFA4WZxdEF4tXPZVKMLwD8oUnCTTo08duU7wxecdEvA=
github.com/mattn/go-colorable v0.1.13/go.mod h1:7S9/ev0klgBDR4GtXTXX8a3vIGJpMovkB8vQcUbaXHg=
github.com/mattn/go-isatty v0.0.16/go.mod h1:kYGgaQfpe5nmfYZH+SKPsOc2e4SrIfOl2e/yFXSvRLM=
github.com/mattn/go-isatty v0.0.19 h1:JITubQf0MOLdlGRuRq+jtsDlekdYPia9ZFsB8h/APPA=
github.com/mattn/go-isatty v0.0.19/go.mod h1:W+V8PltTTMOvKvAeJH7IuucS94S2C6jfK/D7dTCTo3Y=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4/go.mod h1:xMI15A0UPsDsEKsMN9yxemIoYk6Tm2C1GtYGdfGttqA=
github.com/rs/xid v1.5.0/go.mod h1:trrq9SKmegXys3aeAKXMUTdJsYXVwGY3RLcfgqegfbg=
github.com/rs/zerolog v1.33.0 h1:1cU2KZkvPxNyfgEmhHAz/1A9Bz+llsdYzklWFzgp0r8=
github.com/rs/zerolog v1.33.0/go.mod h1:/7mN4D5sKwJLZQ2b/znpjC3/GQWY/xaDXUM0kKWRHss=
github.com/russross/blackfriday/v2 v2.1.0/go.mod h1:+Rmxgy9KzJVeS9/2gXHxylqXiyQDYRxCVz55jmeOWTM=
github.com/spf13/cobra v1.8.1 h1:e5/vxKd/rZsfSJMUX1agtjeTDf+qv1/JdBF8gg5k9ZM=
github.com/spf13/cobra v1.8.1/go.mod h1:wHxEcudfqmLYa8iTfL+OuZPbBZkmvliBWKIezN3kD9Y=
github.com/spf13/pflag v1.0.5 h1:iy+VFUOCP1a+8yFto/drg2CJ5u0yRoB7fZw3DKv/JXA=
github.com/spf13/pflag v1.0.5/go.mod h1:McXfInJRrz4CZXVZOBLb0bTZqETkiAhM9Iw0y3An2Bg=
github.com/stretchr/objx v0.1.0/go.mod h1:HFkY916IF+rwdDfMAkV7OtwuqBVzrE8GR6GFx+wExME=
github.com/stretchr/objx v0.4.0/go.mod h1:YvHI0jy2hoMjB+UWwv71VJQ9isScKT/TqJzVSSt89Yw=
github.com/stretchr/objx v0.5.0/go.mod h1:Yh+to48EsGEfYuaHDzXPcE3xhTkx73EhmCGUpEOglKo=
github.com/stretchr/testify v1.7.1/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
github.com/stretchr/testify v1.8.0/go.mod h1:yNjHg4UonilssWZ8iaSj1OCr/vHnekPRkoO+kdMU+MU=
github.com/stretchr/testify v1.8.1/go.mod h1:w2LPCIKwWwSfY2zedu0+kehJoqGctiVI29o6fzry7u4=
github.com/stretchr/testify v1.9.0 h1:HtqpIVDClZ4nwg75+f6Lvsy/wHu+3BoSGCbBAcpTsTg=
github.com/stretchr/testify v1.9.0/go.mod h1:r2ic/lqez/lEtzL7wO/rwa5dbSLXVDPFyf8C91i36aY=
go.opencensus.io v0.24.0 h1:y73uSU6J157QMP2kn2r30vwW1A2W2WFwSCGnAVxeaD0=
go.opencensus.io v0.24.0/go.mod h1:vNK8G9p7aAivkbmorf4v+7Hgx+Zs0yY+0fOtgBfjQKo=
go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.51.0 h1:A3SayB3rNyt+1S6qpI9mHPkeHTZbD7XILEqWnYZb2l0=
go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.51.0/go.mod h1:27iA5uvhuRNmalO+iEUdVn5ZMj2qy10Mm+XRIpRmyuU=
go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.51.0 h1:Xs2Ncz0gNihqu9iosIZ5SkBbWo5T8JhhLJFMQL1qmLI=
go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.51.0/go.mod h1:vy+2G/6NvVMpwGX/NyLqcC41fxepnuKHk16E6IZUcJc=
go.opentelemetry.io/otel v1.26.0 h1:LQwgL5s/1W7YiiRwxf03QGnWLb2HW4pLiAhaA5cZXBs=
go.opentelemetry.io/otel v1.26.0/go.mod h1:UmLkJHUAidDval2EICqBMbnAd0/m2vmpf/dAM+fvFs4=
go.opentelemetry.io/otel/metric v1.26.0 h1:7S39CLuY5Jgg9CrnA9HHiEjGMF/X2VHvoXGgSllRz30=
go.opentelemetry.io/otel/metric v1.26.0/go.mod h1:SY+rHOI4cEawI9a7N1A4nIg/nTQXe1ccCNWYOJUrpX4=
go.opentelemetry.io/otel/trace v1.26.0 h1:1ieeAUb4y0TE26jUFrCIXKpTuVK7uJGN9/Z/2LP5sQA=
go.opentelemetry.io/otel/trace v1.26.0/go.mod h1:4iDxvGDQuUkHve82hJJ8UqrwswHYsZuWCBllGV2U2y0=
golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2/go.mod h1:djNgcEr1/C05ACkg1iLfiJU5Ep61QUkGW8qpdssI0+w=
golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9/go.mod h1:LzIPMQfyMNhhGPhUkYOs5KpL4U8rLKemX1yGLhDgUto=
golang.org/x/crypto v0.25.0 h1:ypSNr+bnYL2YhwoMt2zPxHFmbAN1KZs/njMG3hxUp30=
golang.org/x/crypto v0.25.0/go.mod h1:T+wALwcMOSE0kXgUAnPAHqTLW+XHgcELELW8VaDgm/M=
golang.org/x/exp v0.0.0-20190121172915-509febef88a4/go.mod h1:CJ0aWSM057203Lf6IL+f9T1iT9GByDxfZKAQTCR3kQA=
golang.org/x/lint v0.0.0-20181026193005-c67002cb31c3/go.mod h1:UVdnD1Gm6xHRNCYTkRU2/jEulfH38KcIWyp/GAMgvoE=
golang.org/x/lint v0.0.0-20190227174305-5b3e6a55c961/go.mod h1:wehouNa3lNwaWXcvxsM5YxQ5yQlVC4a0KAMCusXpPoU=
golang.org/x/lint v0.0.0-20190313153728-d0100b6bd8b3/go.mod h1:6SW0HCj/g11FgYtHlgUYUwCkIfeOF89ocIRzGO/8vkc=
golang.org/x/net v0.0.0-20180724234803-3673e40ba225/go.mod h1:mL1N/T3taQHkDXs73rZJwtUhF3w3ftmwwsq0BUmARs4=
golang.org/x/net v0.0.0-20180826012351-8a410e7b638d/go.mod h1:mL1N/T3taQHkDXs73rZJwtUhF3w3ftmwwsq0BUmARs4=
golang.org/x/net v0.0.0-20190213061140-3a22650c66bd/go.mod h1:mL1N/T3taQHkDXs73rZJwtUhF3w3ftmwwsq0BUmARs4=
golang.org/x/net v0.0.0-20190311183353-d8887717615a/go.mod h1:t9HGtf8HONx5eT2rtn7q6eTqICYqUVnKs3thJo3Qplg=
golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3/go.mod h1:t9HGtf8HONx5eT2rtn7q6eTqICYqUVnKs3thJo3Qplg=
golang.org/x/net v0.0.0-20201110031124-69a78807bb2b/go.mod h1:sp8m0HH+o8qH0wwXwYZr8TS3Oi6o0r6Gce1SSxlDquU=
golang.org/x/net v0.27.0 h1:5K3Njcw06/l2y9vpGCSdcxWOYHOUk3dVNGDXN+FvAys=
golang.org/x/net v0.27.0/go.mod h1:dDi0PyhWNoiUOrAS8uXv/vnScO4wnHQO4mj9fn/RytE=
golang.org/x/oauth2 v0.0.0-20180821212333-d2e6202438be/go.mod h1:N/0e6XlmueqKjAGxoOufVs8QHGRruUQn6yWY3a++T0U=
golang.org/x/oauth2 v0.21.0 h1:tsimM75w1tF/uws5rbeHzIWxEqElMehnc+iW793zsZs=
golang.org/x/oauth2 v0.21.0/go.mod h1:XYTD2NtWslqkgxebSiOHnXEap4TF09sJSc7H1sXbhtI=
golang.org/x/sync v0.0.0-20180314180146-1d60e4601c6f/go.mod h1:RxMgew5VJxzue5/jJTE5uejpjVlOe/izrB70Jof72aM=
golang.org/x/sync v0.0.0-20181108010431-42b317875d0f/go.mod h1:RxMgew5VJxzue5/jJTE5uejpjVlOe/izrB70Jof72aM=
golang.org/x/sync v0.0.0-20190423024810-112230192c58/go.mod h1:RxMgew5VJxzue5/jJTE5uejpjVlOe/izrB70Jof72aM=
golang.org/x/sync v0.7.0 h1:YsImfSBoP9QPYL0xyKJPq0gcaJdG3rInoqxTWbfQu9M=
golang.org/x/sync v0.7.0/go.mod h1:Czt+wKu1gCyEFDUtn0jG5QVvpJ6rzVqr5aXyt9drQfk=
golang.org/x/sys v0.0.0-20180830151530-49385e6e1522/go.mod h1:STP8DvDyc/dI5b8T5hshtkjS+E42TnysNCUPdjciGhY=
golang.org/x/sys v0.0.0-20190215142949-d0b11bdaac8a/go.mod h1:STP8DvDyc/dI5b8T5hshtkjS+E42TnysNCUPdjciGhY=
golang.org/x/sys v0.0.0-20190412213103-97732733099d/go.mod h1:h1NjWce9XRLGQEsW7wpKNCjG9DtNlClVuFLEZdDNbEs=
golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f/go.mod h1:h1NjWce9XRLGQEsW7wpKNCjG9DtNlClVuFLEZdDNbEs=
golang.org/x/sys v0.0.0-20220811171246-fbc7d0a398ab/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.6.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.12.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.22.0 h1:RI27ohtqKCnwULzJLqkv897zojh5/DwS/ENaMzUOaWI=
golang.org/x/sys v0.22.0/go.mod h1:/VUhepiaJMQUp4+oa/7Zr1D23ma6VTLIYjOOTFZPUcA=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
golang.org/x/text v0.3.3/go.mod h1:5Zoc/QRtKVWzQhOtBMvqHzDpF6irO9z98xDceosuGiQ=
golang.org/x/text v0.16.0 h1:a94ExnEXNtEwYLGJSIUxnWoxoRz/ZcCsV63ROupILh4=
golang.org/x/text v0.16.0/go.mod h1:GhwF1Be+LQoKShO3cGOHzqOgRrGaYc9AvblQOmPVHnI=
golang.org/x/time v0.5.0 h1:o7cqy6amK/52YcAKIPlM3a+Fpj35zvRj2TP+e1xFSfk=
golang.org/x/time v0.5.0/go.mod h1:3BpzKBy/shNhVucY/MWOyx10tF3SFh9QdLuxbVysPQM=
golang.org/x/tools v0.0.0-20180917221912-90fa682c2a6e/go.mod h1:n7NCudcB/nEzxVGmLbDWY5pfWTLqBcC2KZ6jyYvM4mQ=
golang.org/x/tools v0.0.0-20190114222345-bf090417da8b/go.mod h1:n7NCudcB/nEzxVGmLbDWY5pfWTLqBcC2KZ6jyYvM4mQ=
golang.org/x/tools v0.0.0-20190226205152-f727befe758c/go.mod h1:9Yl7xja0Znq3iFh3HoIrodX9oNMXvdceNzlUR8zjMvY=
golang.org/x/tools v0.0.0-20190311212946-11955173bddd/go.mod h1:LCzVGOaR6xXOjkQ3onu1FJEFr0SW1gC7cKk1uF8kGRs=
golang.org/x/tools v0.0.0-20190524140312-2c0ae7006135/go.mod h1:RgjU9mgBXZiqYHBnxXauZ1Gv1EHHAz9KjViQ78xBX0Q=
golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543/go.mod h1:I/5z698sn9Ka8TeJc9MKroUUfqBBauWjQqLJ2OPfmY0=
google.golang.org/api v0.189.0 h1:equMo30LypAkdkLMBqfeIqtyAnlyig1JSZArl4XPwdI=
google.golang.org/api v0.189.0/go.mod h1:FLWGJKb0hb+pU2j+rJqwbnsF+ym+fQs73rbJ+KAUgy8=
google.golang.org/appengine v1.1.0/go.mod h1:EbEs0AVv82hx2wNQdGPgUI5lhzA/G0D9YwlJXL52JkM=
google.golang.org/appengine v1.4.0/go.mod h1:xpcJRLb0r/rnEns0DIKYYv+WjYCduHsrkT7/EB5XEv4=
google.golang.org/genproto v0.0.0-20180817151627-c66870c02cf8/go.mod h1:JiN7NxoALGmiZfu7CAH4rXhgtRTLTxftemlI0sWmxmc=
google.golang.org/genproto v0.0.0-20190819201941-24fa4b261c55/go.mod h1:DMBHOl98Agz4BDEuKkezgsaosCRResVns1a3J2ZsMNc=
google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013/go.mod h1:NbSheEEYHJ7i3ixzK3sjbqSGDJWnxyFXZblF3eUsNvo=
google.golang.org/genproto/googleapis/api v0.0.0-20240722135656-d784300faade h1:WxZOF2yayUHpHSbUE6NMzumUzBxYc3YGwo0YHnbzsJY=
google.golang.org/genproto/googleapis/api v0.0.0-20240722135656-d784300faade/go.mod h1:mw8MG/Qz5wfgYr6VqVCiZcHe/GJEfI+oGGDCohaVgB0=
google.golang.org/genproto/googleapis/rpc v0.0.0-20240722135656-d784300faade h1:oCRSWfwGXQsqlVdErcyTt4A93Y8fo0/9D4b1gnI++qo=
google.golang.org/genproto/googleapis/rpc v0.0.0-20240722135656-d784300faade/go.mod h1:Ue6ibwXGpU+dqIcODieyLOcgj7z8+IcskoNIgZxtrFY=
google.golang.org/grpc v1.19.0/go.mod h1:mqu4LbDTu4XGKhr4mRzUsmM4RtVoemTSY81AxZiDr8c=
google.golang.org/grpc v1.23.0/go.mod h1:Y5yQAOtifL1yxbo5wqy6BxZv8vAUGQwXBOALyacEbxg=
google.golang.org/grpc v1.25.1/go.mod h1:c3i+UQWmh7LiEpx4sFZnkU36qjEYZ0imhYfXVyQciAY=
google.golang.org/grpc v1.27.0/go.mod h1:qbnxyOmOxrQa7FizSgH+ReBfzJrCY1pSN7KXBS8abTk=
google.golang.org/grpc v1.33.2/go.mod h1:JMHMWHQWaTccqQQlmk3MJZS+GWXOdAesneDmEnv2fbc=
google.golang.org/grpc v1.65.0 h1:bs/cUb4lp1G5iImFFd3u5ixQzweKizoZJAwBNLR42lc=
google.golang.org/grpc v1.65.0/go.mod h1:WgYC2ypjlB0EiQi6wdKixMqukr6lBc0Vo+oOgjrM5ZQ=
google.golang.org/protobuf v0.0.0-20200109180630-ec00e32a8dfd/go.mod h1:DFci5gLYBciE7Vtevhsrf46CRTquxDuWsQurQQe4oz8=
google.golang.org/protobuf v0.0.0-20200221191635-4d8936d0db64/go.mod h1:kwYJMbMJ01Woi6D6+Kah6886xMZcty6N08ah7+eCXa0=
google.golang.org/protobuf v0.0.0-20200228230310-ab0ca4ff8a60/go.mod h1:cfTl7dwQJ+fmap5saPgwCLgHXTUD7jkjRqWcaiX5VyM=
google.golang.org/protobuf v1.20.1-0.20200309200217-e05f789c0967/go.mod h1:A+miEFZTKqfCUM6K7xSMQL9OKL/b6hQv+e19PK+JZNE=
google.golang.org/protobuf v1.21.0/go.mod h1:47Nbq4nVaFHyn7ilMalzfO3qCViNmqZ2kzikPIcrTAo=
google.golang.org/protobuf v1.22.0/go.mod h1:EGpADcykh3NcUnDUJcl1+ZksZNG86OlYog2l/sGQquU=
google.golang.org/protobuf v1.23.0/go.mod h1:EGpADcykh3NcUnDUJcl1+ZksZNG86OlYog2l/sGQquU=
google.golang.org/protobuf v1.23.1-0.20200526195155-81db48ad09cc/go.mod h1:EGpADcykh3NcUnDUJcl1+ZksZNG86OlYog2l/sGQquU=
google.golang.org/protobuf v1.25.0/go.mod h1:9JNX74DMeImyA3h4bdi1ymwjUzf21/xIlbajtzgsN7c=
google.golang.org/protobuf v1.34.2 h1:6xV6lTsCfpGD21XK49h7MhtcApnLqkfYgPcdHftf6hg=
google.golang.org/protobuf v1.34.2/go.mod h1:qYOHts0dSfpeUzUFpOMr/WGzszTmLH+DiWniOlNbLDw=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
honnef.co/go/tools v0.0.0-20190102054323-c2f93a96b099/go.mod h1:rf3lG4BRIbNafJWhAfAdb/ePZxsR/4RtNHQocxwk9r4=
honnef.co/go/tools v0.0.0-20190523083050-ea95bdfd59fc/go.mod h1:rf3lG4BRIbNafJWhAfAdb/ePZxsR/4RtNHQocxwk9r4=

```

`internal/config/config.go`:

```go
package config

import (
	_ "embed"
	"regexp"

	"github.com/BurntSushi/toml"
	"github.com/rs/zerolog/log"
)

//go:embed gitleaks.toml
var defaultRules string

// ViperConfig is a temporary struct to match the TOML structure for parsing.
type ViperConfig struct {
	Rules []struct {
		ID          string
		Description string
		Regex       string
		SecretGroup int
		Entropy     float64
		Keywords    []string
	}
}

type Rule struct {
	ID          string
	Description string
	Regex       *regexp.Regexp
	SecretGroup int
	Keywords    []string
	Entropy     float64
}

type Config struct {
	Rules []Rule
}

func Load() (*Config, error) {
	var vc ViperConfig
	if _, err := toml.Decode(defaultRules, &vc); err != nil {
		return nil, err
	}

	var cfg Config
	for _, vr := range vc.Rules {
		re, err := regexp.Compile(vr.Regex)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to compile regex for rule %s", vr.ID)
			continue
		}

		newRule := Rule{
			ID:          vr.ID,
			Description: vr.Description,
			Regex:       re,
			SecretGroup: vr.SecretGroup,
			Keywords:    vr.Keywords,
			Entropy:     vr.Entropy,
		}
		cfg.Rules = append(cfg.Rules, newRule)
	}

	return &cfg, nil
}

```

`internal/config/gitleaks.toml`:

```toml
[[rules]]
id = "aws-access-token"
description = "AWS Access Token"
regex = '''\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b'''
keywords = ["AKIA", "ASIA"]

[[rules]]
id = "github-pat"
description = "GitHub Personal Access Token"
regex = '''ghp_[0-9a-zA-Z]{36}'''
keywords = ["ghp_"]

[[rules]]
id = "slack-webhook-url"
description = "Slack Webhook"
regex = '''https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}'''
keywords = ["hooks.slack.com"]

[[rules]]
id = "private-key"
description = "Asymmetric Private Key"
regex = '''-----BEGIN (?:[A-Z\s]+) PRIVATE KEY-----'''
keywords = ["-----BEGIN"]

[[rules]]
id = "generic-api-key"
description = "Generic API Key"
regex = '''(?i)(key|api|token|secret|password)"?\s*[:=]\s*["']([0-9a-zA-Z\-_.=]{20,})["']'''
secretGroup = 2
entropy = 3.5
keywords = ["key", "api", "token", "secret", "password"]
```

`internal/genai/gemini.go`:

```go
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

```

`internal/scanner/scanner.go`:

```go
package scanner

import (
	"gitleaks-lite/internal/config"
	"strings"

	"github.com/gitleaks/go-gitdiff/gitdiff"
)

// Finding represents a secret that has been found.
type Finding struct {
	RuleID      string
	File        string
	StartLine   int
	Secret      string
	Commit      string
	Author      string
	Email       string
	Date        string
	Message     string
	CodeContext string
}

type Scanner struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Scanner {
	return &Scanner{cfg: cfg}
}

// Scan performs the detection on a single gitdiff file.
func (s *Scanner) Scan(file *gitdiff.File) []Finding {
	var findings []Finding
	if file == nil || file.PatchHeader == nil {
		return findings
	}

	for _, textFragment := range file.TextFragments {
		if textFragment == nil {
			continue
		}

		content := textFragment.Raw(gitdiff.OpAdd)
		lines := strings.Split(content, "\n")

		for i, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if strings.Contains(line, "gitleaks:allow") {
				continue
			}

			for _, rule := range s.cfg.Rules {
				matches := rule.Regex.FindAllStringSubmatch(line, -1)
				if matches == nil {
					continue
				}

				for _, match := range matches {
					secret := ""
					// Safely determine the secret.
					if len(match) > rule.SecretGroup {
						secret = match[rule.SecretGroup]
					}
					// If a specific group is requested but empty, or not set, use the full match.
					if secret == "" {
						secret = match[0]
					}
					if secret == "" {
						continue
					}

					start := i - 2
					if start < 0 {
						start = 0
					}
					end := i + 3
					if end > len(lines) {
						end = len(lines)
					}
					contextSnippet := strings.Join(lines[start:end], "\n")

					findings = append(findings, Finding{
						RuleID:      rule.ID,
						File:        file.NewName,
						StartLine:   int(textFragment.NewPosition) + i,
						Secret:      secret,
						Commit:      file.PatchHeader.SHA,
						Author:      file.PatchHeader.Author.Name,
						Email:       file.PatchHeader.Author.Email,
						Date:        file.PatchHeader.AuthorDate.String(),
						Message:     file.PatchHeader.Message(),
						CodeContext: contextSnippet,
					})
				}
			}
		}
	}
	return findings
}

```

`main.go`:

```go
package main

import (
	"gitleaks-lite/cmd"
	"os"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

```

`run_tests.sh`:

```sh
#!/bin/bash

# --- Self-sufficient PATH configuration ---
if ! command -v go &> /dev/null; then
    echo "[SETUP] 'go' command not found. Adding default Go path to environment..."
    export PATH=$PATH:/usr/local/go/bin
fi
if ! command -v go &> /dev/null; then
    echo "[ERROR] Could not find 'go' executable." >&2
    exit 1
fi

set -e

# --- Configuration ---
DOCKER_IMAGE_NAME="gitleaks-lite-test"
REPO_CLEAN_PATH="$(pwd)/testdata/repos/repo-clean"
REPO_SECRET_PATH="$(pwd)/testdata/repos/repo-with-secret"
REPO_FP_PATH="$(pwd)/testdata/repos/repo-with-false-positive"

# --- Helper Functions for Logging ---
info() { echo -e "\033[0;34m[INFO]\033[0m $1"; }
success() { echo -e "\033[0;32m[SUCCESS]\033[0m $1"; }
error() { echo -e "\033[0;31m[ERROR]\033[0m $1" >&2; exit 1; }

# --- Test Runner Logic ---

info "--- Phase 1: Linting and Formatting ---"
FMT_OUTPUT=$(go fmt ./...)
if [ -n "$FMT_OUTPUT" ]; then
    error "Go files are not formatted. Please run 'go fmt ./...'\nFiles changed:\n$FMT_OUTPUT"
fi
go vet ./...
success "Code is well-formatted and passes vet checks."

info "\n--- Phase 2: Building Test Docker Image ---"
docker build -t "$DOCKER_IMAGE_NAME" .
success "Docker image '$DOCKER_IMAGE_NAME' built successfully."

info "\n--- Phase 3: Running Integration Tests ---"

# --- REMOVED THE -u FLAG FROM ALL DOCKER COMMANDS ---
BASE_DOCKER_RUN="docker run --rm"

# Test 1: Clean Repo - Expect exit code 0
info "Running test on clean repository..."
set +e
output_clean=$($BASE_DOCKER_RUN -v "$REPO_CLEAN_PATH:/scan" "$DOCKER_IMAGE_NAME" git /scan 2>&1)
exit_code_clean=$?
set -e

if [ $exit_code_clean -ne 0 ]; then
    error "Expected exit code 0 for clean repo, but got $exit_code_clean. Output:\n$output_clean"
fi
if ! echo "$output_clean" | grep -q "No secrets found"; then
    error "Expected 'No secrets found' for clean repo. Output:\n$output_clean"
fi
success "Clean repository test passed."

# Test 2: Repo with Secret (Regex-Only) - Expect exit code 1
info "\nRunning test on repo with secret (regex-only)..."
set +e
output_secret=$($BASE_DOCKER_RUN -v "$REPO_SECRET_PATH:/scan" "$DOCKER_IMAGE_NAME" git /scan 2>&1)
exit_code_secret=$?
set -e

if [ $exit_code_secret -ne 1 ]; then
    error "Expected exit code 1 for repo with secret, but got $exit_code_secret. Output:\n$output_secret"
fi
if ! echo "$output_secret" | grep -q "github-pat"; then
    error "Expected finding for rule 'github-pat' was not found. Output:\n$output_secret"
fi
success "Repo with secret (regex-only) test passed."

# GenAI related tests
if [ -z "$GEMINI_API_KEY" ]; then
    info "\n--- Skipping GenAI tests: GEMINI_API_KEY not set ---"
else
    info "\nGEMINI_API_KEY found. Proceeding with GenAI integration tests."

    # Test 3: Repo with Secret (GenAI Mode) - Expect exit code 1
    info "Running test on repo with secret (GenAI mode)..."
    set +e
    output_secret_ai=$($BASE_DOCKER_RUN -v "$REPO_SECRET_PATH:/scan" -e GEMINI_API_KEY="$GEMINI_API_KEY" "$DOCKER_IMAGE_NAME" git /scan 2>&1)
    exit_code_secret_ai=$?
    set -e

    if [ $exit_code_secret_ai -ne 1 ]; then
        error "Expected exit code 1 for repo with secret (GenAI mode), but got $exit_code_secret_ai. Output:\n$output_secret_ai"
    fi
    if ! echo "$output_secret_ai" | grep -q "github-pat"; then
        error "Expected finding for 'github-pat' not found in GenAI mode. Output:\n$output_secret_ai"
    fi
    success "Repo with secret (GenAI mode) test passed (True Positive Confirmed)."

    # Test 4: Repo with False Positive (GenAI Mode) - Expect exit code 0
    info "\nRunning test on repo with false positive (GenAI mode)..."
    set +e
    output_fp_ai=$($BASE_DOCKER_RUN -v "$REPO_FP_PATH:/scan" -e GEMINI_API_KEY="$GEMINI_API_KEY" "$DOCKER_IMAGE_NAME" git /scan 2>&1)
    exit_code_fp_ai=$?
    set -e
    
    if [ $exit_code_fp_ai -ne 0 ]; then
        error "Expected exit code 0 for repo with false positive (GenAI mode), but got $exit_code_fp_ai. Output:\n$output_fp_ai"
    fi
    if ! echo "$output_fp_ai" | grep -q "No secrets found"; then
        error "Expected 'No secrets found' for false positive repo. Output:\n$output_fp_ai"
    fi
    success "Repo with false positive (GenAI mode) test passed (False Positive Filtered)."
fi

info "\n--- Phase 4: Cleaning up ---"
# docker rmi "$DOCKER_IMAGE_NAME"
# success "Test Docker image '$DOCKER_IMAGE_NAME' removed."

echo ""
success "✅ ✅ ✅ ALL TESTS PASSED! ✅ ✅ ✅"
```

`scan_all_repos.sh`:

```sh
#!/bin/bash

# --- Configuration ---
SCAN_DIRECTORY="/home/mdt/dev"
DOCKER_IMAGE="gitleaks-lite:latest"
USE_GEMINI=true
SCAN_TIMEOUT="2m" # Set a 2-minute timeout for each repository scan.

# --- Helper function for logging ---
info() {
    echo -e "\033[0;34m[INFO]\033[0m $1"
}

# --- Script Logic ---

# Step 1: Handle API Key securely at the very beginning.
if [ "$USE_GEMINI" = true ] && [ -z "$GEMINI_API_KEY" ]; then
    echo "GenAI validation is enabled, but GEMINI_API_KEY is not set."
    read -sp "Please enter your Gemini API Key (or press Enter to skip GenAI scans): " temp_api_key
    echo
    if [ -n "$temp_api_key" ]; then
        export GEMINI_API_KEY="$temp_api_key"
        info "GEMINI_API_KEY has been set for this session."
    else
        info "No API key provided. GenAI validation will be skipped."
        USE_GEMINI=false
    fi
fi

echo "--- Starting Gitleaks-Lite Scan on all repositories in $SCAN_DIRECTORY ---"
echo "--- Timeout per repository is set to $SCAN_TIMEOUT ---"

repos_with_findings=0
start_time=$SECONDS

# Step 2: Loop through directories and scan.
for dir in "$SCAN_DIRECTORY"/*/; do
    if [ -d "$dir" ]; then
        repo_path=$(realpath "$dir")
        repo_name=$(basename "$repo_path")

        if git -C "$repo_path" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
            echo ""
            echo "========================================================================"
            echo "Scanning repository: $repo_name"
            echo "========================================================================"

            docker_args=( "run" "--rm" "-v" "$repo_path:/scan" )

            if [ "$USE_GEMINI" = true ] && [ -n "$GEMINI_API_KEY" ]; then
                docker_args+=("-e" "GEMINI_API_KEY=$GEMINI_API_KEY")
            fi

            docker_args+=("$DOCKER_IMAGE" "git" "/scan")

            # Execute the command with a timeout. This simplified execution is more stable.
            # The output will appear when the command finishes or times out.
            if output=$(timeout --foreground "$SCAN_TIMEOUT" docker "${docker_args[@]}" 2>&1); then
                # Exit code 0 (success)
                echo "$output"
            else
                status=$?
                if [ $status -eq 124 ]; then
                    echo "❌ ERROR: Scan for $repo_name timed out after $SCAN_TIMEOUT."
                elif [ $status -eq 1 ]; then
                    echo "$output"
                    echo "🚨🚨🚨 WARNING: Secrets found in $repo_name 🚨🚨🚨"
                    repos_with_findings=$((repos_with_findings + 1))
                else
                    echo "❌ ERROR: Scan for $repo_name failed with an unexpected error (exit code $status)."
                    echo "--- Error Output ---"
                    echo "$output"
                    echo "--------------------"
                fi
            fi
        else
            echo "-> Skipping '$repo_name' (not a Git repository)"
        fi
    fi
done

end_time=$SECONDS
duration=$((end_time - start_time))

echo ""
echo "========================================================================"
echo "--- Scan Complete ---"
echo "Total execution time: $((duration / 60)) minutes and $((duration % 60)) seconds."
if [ $repos_with_findings -gt 0 ]; then
    echo "Total repositories with findings: $repos_with_findings"
    exit 1
else
    echo "✅ No secrets found in any repository."
fi
```

`testdata/repos/repo-clean/README.md`:

```md
This is a clean repository with no secrets.

```

`testdata/repos/repo-with-false-positive/examples.py`:

```py
# This is an example key for documentation purposes only.
# It is not a real production secret.
EXAMPLE_API_KEY = "key_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmN"

```

`testdata/repos/repo-with-secret/config.yml`:

```yml
api_key: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmN"

```
```

`entrypoint.sh`:

```sh
#!/bin/sh

# This script runs every time the container starts.

# The `git` command expects to run in a directory, but our scanner
# specifies the path. We'll run this from the root. The scanner will
# use the correct path provided in its arguments.
git config --global --add safe.directory /scan

# Now, execute the main gitleaks-lite application, passing along
# all the arguments that were given to the container.
exec gitleaks-lite "$@"

```

`go.mod`:

```mod
module gitleaks-lite

go 1.23

require (
	github.com/BurntSushi/toml v1.4.0
	github.com/gitleaks/go-gitdiff v0.9.1
	github.com/google/generative-ai-go v0.15.0
	github.com/rs/zerolog v1.33.0
	github.com/spf13/cobra v1.8.1
	google.golang.org/api v0.189.0
)

require (
	cloud.google.com/go v0.115.0 // indirect
	cloud.google.com/go/ai v0.8.0 // indirect
	cloud.google.com/go/auth v0.7.2 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.3 // indirect
	cloud.google.com/go/compute/metadata v0.5.0 // indirect
	cloud.google.com/go/longrunning v0.5.9 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/googleapis/gax-go/v2 v2.13.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.51.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.51.0 // indirect
	go.opentelemetry.io/otel v1.26.0 // indirect
	go.opentelemetry.io/otel/metric v1.26.0 // indirect
	go.opentelemetry.io/otel/trace v1.26.0 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/net v0.27.0 // indirect
	golang.org/x/oauth2 v0.21.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240722135656-d784300faade // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240722135656-d784300faade // indirect
	google.golang.org/grpc v1.65.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

```

`go.sum`:

```sum
cloud.google.com/go v0.26.0/go.mod h1:aQUYkXzVsufM+DwF1aE+0xfcU+56JwCaLick0ClmMTw=
cloud.google.com/go v0.115.0 h1:CnFSK6Xo3lDYRoBKEcAtia6VSC837/ZkJuRduSFnr14=
cloud.google.com/go v0.115.0/go.mod h1:8jIM5vVgoAEoiVxQ/O4BFTfHqulPZgs/ufEzMcFMdWU=
cloud.google.com/go/ai v0.8.0 h1:rXUEz8Wp2OlrM8r1bfmpF2+VKqc1VJpafE3HgzRnD/w=
cloud.google.com/go/ai v0.8.0/go.mod h1:t3Dfk4cM61sytiggo2UyGsDVW3RF1qGZaUKDrZFyqkE=
cloud.google.com/go/auth v0.7.2 h1:uiha352VrCDMXg+yoBtaD0tUF4Kv9vrtrWPYXwutnDE=
cloud.google.com/go/auth v0.7.2/go.mod h1:VEc4p5NNxycWQTMQEDQF0bd6aTMb6VgYDXEwiJJQAbs=
cloud.google.com/go/auth/oauth2adapt v0.2.3 h1:MlxF+Pd3OmSudg/b1yZ5lJwoXCEaeedAguodky1PcKI=
cloud.google.com/go/auth/oauth2adapt v0.2.3/go.mod h1:tMQXOfZzFuNuUxOypHlQEXgdfX5cuhwU+ffUuXRJE8I=
cloud.google.com/go/compute/metadata v0.5.0 h1:Zr0eK8JbFv6+Wi4ilXAR8FJ3wyNdpxHKJNPos6LTZOY=
cloud.google.com/go/compute/metadata v0.5.0/go.mod h1:aHnloV2TPI38yx4s9+wAZhHykWvVCfu7hQbF+9CWoiY=
cloud.google.com/go/longrunning v0.5.9 h1:haH9pAuXdPAMqHvzX0zlWQigXT7B0+CL4/2nXXdBo5k=
cloud.google.com/go/longrunning v0.5.9/go.mod h1:HD+0l9/OOW0za6UWdKJtXoFAX/BGg/3Wj8p10NeWF7c=
github.com/BurntSushi/toml v0.3.1/go.mod h1:xHWCNGjB5oqiDr8zfno3MHue2Ht5sIBksp03qcyfWMU=
github.com/BurntSushi/toml v1.4.0 h1:kuoIxZQy2WRRk1pttg9asf+WVv6tWQuBNVmK8+nqPr0=
github.com/BurntSushi/toml v1.4.0/go.mod h1:ukJfTF/6rtPPRCnwkur4qwRxa8vTRFBF0uk2lLoLwho=
github.com/census-instrumentation/opencensus-proto v0.2.1/go.mod h1:f6KPmirojxKA12rnyqOA5BBL4O983OfeGPqjHWSTneU=
github.com/client9/misspell v0.3.4/go.mod h1:qj6jICC3Q7zFZvVWo7KLAzC3yx5G7kyvSDkc90ppPyw=
github.com/cncf/udpa/go v0.0.0-20191209042840-269d4d468f6f/go.mod h1:M8M6+tZqaGXZJjfX53e64911xZQV5JYwmTeXPW+k8Sc=
github.com/coreos/go-systemd/v22 v22.5.0/go.mod h1:Y58oyj3AT4RCenI/lSvhwexgC+NSVTIJ3seZv2GcEnc=
github.com/cpuguy83/go-md2man/v2 v2.0.4/go.mod h1:tgQtvFlXSQOSOSIRvRPT7W67SCa46tRHOmNcaadrF8o=
github.com/davecgh/go-spew v1.1.0/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/davecgh/go-spew v1.1.1 h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=
github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/envoyproxy/go-control-plane v0.9.0/go.mod h1:YTl/9mNaCwkRvm6d1a2C3ymFceY/DCBVvsKhRF0iEA4=
github.com/envoyproxy/go-control-plane v0.9.1-0.20191026205805-5f8ba28d4473/go.mod h1:YTl/9mNaCwkRvm6d1a2C3ymFceY/DCBVvsKhRF0iEA4=
github.com/envoyproxy/go-control-plane v0.9.4/go.mod h1:6rpuAdCZL397s3pYoYcLgu1mIlRU8Am5FuJP05cCM98=
github.com/envoyproxy/protoc-gen-validate v0.1.0/go.mod h1:iSmxcyjqTsJpI2R4NaDN7+kN2VEUnK/pcBlmesArF7c=
github.com/felixge/httpsnoop v1.0.4 h1:NFTV2Zj1bL4mc9sqWACXbQFVBBg2W3GPvqp8/ESS2Wg=
github.com/felixge/httpsnoop v1.0.4/go.mod h1:m8KPJKqk1gH5J9DgRY2ASl2lWCfGKXixSwevea8zH2U=
github.com/gitleaks/go-gitdiff v0.9.1 h1:ni6z6/3i9ODT685OLCTf+s/ERlWUNWQF4x1pvoNICw0=
github.com/gitleaks/go-gitdiff v0.9.1/go.mod h1:pKz0X4YzCKZs30BL+weqBIG7mx0jl4tF1uXV9ZyNvrA=
github.com/go-logr/logr v1.2.2/go.mod h1:jdQByPbusPIv2/zmleS9BjJVeZ6kBagPoEUsqbVz/1A=
github.com/go-logr/logr v1.4.2 h1:6pFjapn8bFcIbiKo3XT4j/BhANplGihG6tvd+8rYgrY=
github.com/go-logr/logr v1.4.2/go.mod h1:9T104GzyrTigFIr8wt5mBrctHMim0Nb2HLGrmQ40KvY=
github.com/go-logr/stdr v1.2.2 h1:hSWxHoqTgW2S2qGc0LTAI563KZ5YKYRhT3MFKZMbjag=
github.com/go-logr/stdr v1.2.2/go.mod h1:mMo/vtBO5dYbehREoey6XUKy/eSumjCCveDpRre4VKE=
github.com/godbus/dbus/v5 v5.0.4/go.mod h1:xhWf0FNVPg57R7Z0UbKHbJfkEywrmjJnf7w5xrFpKfA=
github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b/go.mod h1:SBH7ygxi8pfUlaOkMMuAQtPIUF8ecWP5IEl/CR7VP2Q=
github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e/go.mod h1:cIg4eruTrX1D+g88fzRXU5OdNfaM+9IcxsU14FzY7Hc=
github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da h1:oI5xCqsCo564l8iNU+DwB5epxmsaqB+rhGL0m5jtYqE=
github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da/go.mod h1:cIg4eruTrX1D+g88fzRXU5OdNfaM+9IcxsU14FzY7Hc=
github.com/golang/mock v1.1.1/go.mod h1:oTYuIxOrZwtPieC+H1uAHpcLFnEyAGVDL/k47Jfbm0A=
github.com/golang/protobuf v1.2.0/go.mod h1:6lQm79b+lXiMfvg/cZm0SGofjICqVBUtrP5yJMmIC1U=
github.com/golang/protobuf v1.3.2/go.mod h1:6lQm79b+lXiMfvg/cZm0SGofjICqVBUtrP5yJMmIC1U=
github.com/golang/protobuf v1.4.0-rc.1/go.mod h1:ceaxUfeHdC40wWswd/P6IGgMaK3YpKi5j83Wpe3EHw8=
github.com/golang/protobuf v1.4.0-rc.1.0.20200221234624-67d41d38c208/go.mod h1:xKAWHe0F5eneWXFV3EuXVDTCmh+JuBKY0li0aMyXATA=
github.com/golang/protobuf v1.4.0-rc.2/go.mod h1:LlEzMj4AhA7rCAGe4KMBDvJI+AwstrUpVNzEA03Pprs=
github.com/golang/protobuf v1.4.0-rc.4.0.20200313231945-b860323f09d0/go.mod h1:WU3c8KckQ9AFe+yFwt9sWVRKCVIyN9cPHBJSNnbL67w=
github.com/golang/protobuf v1.4.0/go.mod h1:jodUvKwWbYaEsadDk5Fwe5c77LiNKVO9IDvqG2KuDX0=
github.com/golang/protobuf v1.4.1/go.mod h1:U8fpvMrcmy5pZrNK1lt4xCsGvpyWQ/VVv6QDs8UjoX8=
github.com/golang/protobuf v1.4.3/go.mod h1:oDoupMAO8OvCJWAcko0GGGIgR6R6ocIYbsSw735rRwI=
github.com/golang/protobuf v1.5.4 h1:i7eJL8qZTpSEXOPTxNKhASYpMn+8e5Q6AdndVa1dWek=
github.com/golang/protobuf v1.5.4/go.mod h1:lnTiLA8Wa4RWRcIUkrtSVa5nRhsEGBg48fD6rSs7xps=
github.com/google/generative-ai-go v0.15.0 h1:0PQF6ib/72Sa8SfVkqsyzHqgVZH2MxpIa/krpbGDT7E=
github.com/google/generative-ai-go v0.15.0/go.mod h1:AAucpWZjXsDKhQYWvCYuP6d0yB1kX998pJlOW1rAesw=
github.com/google/go-cmp v0.2.0/go.mod h1:oXzfMopK8JAjlY9xF4vHSVASa0yLyX7SntLO5aqRK0M=
github.com/google/go-cmp v0.3.0/go.mod h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=
github.com/google/go-cmp v0.3.1/go.mod h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=
github.com/google/go-cmp v0.4.0/go.mod h1:v8dTdLbMG2kIc/vJvl+f65V22dbkXbowE6jgT/gNBxE=
github.com/google/go-cmp v0.5.0/go.mod h1:v8dTdLbMG2kIc/vJvl+f65V22dbkXbowE6jgT/gNBxE=
github.com/google/go-cmp v0.5.3/go.mod h1:v8dTdLbMG2kIc/vJvl+f65V22dbkXbowE6jgT/gNBxE=
github.com/google/go-cmp v0.6.0 h1:ofyhxvXcZhMsU5ulbFiLKl/XBFqE1GSq7atu8tAmTRI=
github.com/google/go-cmp v0.6.0/go.mod h1:17dUlkBOakJ0+DkrSSNjCkIjxS6bF9zb3elmeNGIjoY=
github.com/google/s2a-go v0.1.7 h1:60BLSyTrOV4/haCDW4zb1guZItoSq8foHCXrAnjBo/o=
github.com/google/s2a-go v0.1.7/go.mod h1:50CgR4k1jNlWBu4UfS4AcfhVe1r6pdZPygJ3R8F0Qdw=
github.com/google/uuid v1.1.2/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/googleapis/enterprise-certificate-proxy v0.3.2 h1:Vie5ybvEvT75RniqhfFxPRy3Bf7vr3h0cechB90XaQs=
github.com/googleapis/enterprise-certificate-proxy v0.3.2/go.mod h1:VLSiSSBs/ksPL8kq3OBOQ6WRI2QnaFynd1DCjZ62+V0=
github.com/googleapis/gax-go/v2 v2.13.0 h1:yitjD5f7jQHhyDsnhKEBU52NdvvdSeGzlAnDPT0hH1s=
github.com/googleapis/gax-go/v2 v2.13.0/go.mod h1:Z/fvTZXF8/uw7Xu5GuslPw+bplx6SS338j1Is2S+B7A=
github.com/inconshreveable/mousetrap v1.1.0 h1:wN+x4NVGpMsO7ErUn/mUI3vEoE6Jt13X2s0bqwp9tc8=
github.com/inconshreveable/mousetrap v1.1.0/go.mod h1:vpF70FUmC8bwa3OWnCshd2FqLfsEA9PFc4w1p2J65bw=
github.com/mattn/go-colorable v0.1.13 h1:fFA4WZxdEF4tXPZVKMLwD8oUnCTTo08duU7wxecdEvA=
github.com/mattn/go-colorable v0.1.13/go.mod h1:7S9/ev0klgBDR4GtXTXX8a3vIGJpMovkB8vQcUbaXHg=
github.com/mattn/go-isatty v0.0.16/go.mod h1:kYGgaQfpe5nmfYZH+SKPsOc2e4SrIfOl2e/yFXSvRLM=
github.com/mattn/go-isatty v0.0.19 h1:JITubQf0MOLdlGRuRq+jtsDlekdYPia9ZFsB8h/APPA=
github.com/mattn/go-isatty v0.0.19/go.mod h1:W+V8PltTTMOvKvAeJH7IuucS94S2C6jfK/D7dTCTo3Y=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4/go.mod h1:xMI15A0UPsDsEKsMN9yxemIoYk6Tm2C1GtYGdfGttqA=
github.com/rs/xid v1.5.0/go.mod h1:trrq9SKmegXys3aeAKXMUTdJsYXVwGY3RLcfgqegfbg=
github.com/rs/zerolog v1.33.0 h1:1cU2KZkvPxNyfgEmhHAz/1A9Bz+llsdYzklWFzgp0r8=
github.com/rs/zerolog v1.33.0/go.mod h1:/7mN4D5sKwJLZQ2b/znpjC3/GQWY/xaDXUM0kKWRHss=
github.com/russross/blackfriday/v2 v2.1.0/go.mod h1:+Rmxgy9KzJVeS9/2gXHxylqXiyQDYRxCVz55jmeOWTM=
github.com/spf13/cobra v1.8.1 h1:e5/vxKd/rZsfSJMUX1agtjeTDf+qv1/JdBF8gg5k9ZM=
github.com/spf13/cobra v1.8.1/go.mod h1:wHxEcudfqmLYa8iTfL+OuZPbBZkmvliBWKIezN3kD9Y=
github.com/spf13/pflag v1.0.5 h1:iy+VFUOCP1a+8yFto/drg2CJ5u0yRoB7fZw3DKv/JXA=
github.com/spf13/pflag v1.0.5/go.mod h1:McXfInJRrz4CZXVZOBLb0bTZqETkiAhM9Iw0y3An2Bg=
github.com/stretchr/objx v0.1.0/go.mod h1:HFkY916IF+rwdDfMAkV7OtwuqBVzrE8GR6GFx+wExME=
github.com/stretchr/objx v0.4.0/go.mod h1:YvHI0jy2hoMjB+UWwv71VJQ9isScKT/TqJzVSSt89Yw=
github.com/stretchr/objx v0.5.0/go.mod h1:Yh+to48EsGEfYuaHDzXPcE3xhTkx73EhmCGUpEOglKo=
github.com/stretchr/testify v1.7.1/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
github.com/stretchr/testify v1.8.0/go.mod h1:yNjHg4UonilssWZ8iaSj1OCr/vHnekPRkoO+kdMU+MU=
github.com/stretchr/testify v1.8.1/go.mod h1:w2LPCIKwWwSfY2zedu0+kehJoqGctiVI29o6fzry7u4=
github.com/stretchr/testify v1.9.0 h1:HtqpIVDClZ4nwg75+f6Lvsy/wHu+3BoSGCbBAcpTsTg=
github.com/stretchr/testify v1.9.0/go.mod h1:r2ic/lqez/lEtzL7wO/rwa5dbSLXVDPFyf8C91i36aY=
go.opencensus.io v0.24.0 h1:y73uSU6J157QMP2kn2r30vwW1A2W2WFwSCGnAVxeaD0=
go.opencensus.io v0.24.0/go.mod h1:vNK8G9p7aAivkbmorf4v+7Hgx+Zs0yY+0fOtgBfjQKo=
go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.51.0 h1:A3SayB3rNyt+1S6qpI9mHPkeHTZbD7XILEqWnYZb2l0=
go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.51.0/go.mod h1:27iA5uvhuRNmalO+iEUdVn5ZMj2qy10Mm+XRIpRmyuU=
go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.51.0 h1:Xs2Ncz0gNihqu9iosIZ5SkBbWo5T8JhhLJFMQL1qmLI=
go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.51.0/go.mod h1:vy+2G/6NvVMpwGX/NyLqcC41fxepnuKHk16E6IZUcJc=
go.opentelemetry.io/otel v1.26.0 h1:LQwgL5s/1W7YiiRwxf03QGnWLb2HW4pLiAhaA5cZXBs=
go.opentelemetry.io/otel v1.26.0/go.mod h1:UmLkJHUAidDval2EICqBMbnAd0/m2vmpf/dAM+fvFs4=
go.opentelemetry.io/otel/metric v1.26.0 h1:7S39CLuY5Jgg9CrnA9HHiEjGMF/X2VHvoXGgSllRz30=
go.opentelemetry.io/otel/metric v1.26.0/go.mod h1:SY+rHOI4cEawI9a7N1A4nIg/nTQXe1ccCNWYOJUrpX4=
go.opentelemetry.io/otel/trace v1.26.0 h1:1ieeAUb4y0TE26jUFrCIXKpTuVK7uJGN9/Z/2LP5sQA=
go.opentelemetry.io/otel/trace v1.26.0/go.mod h1:4iDxvGDQuUkHve82hJJ8UqrwswHYsZuWCBllGV2U2y0=
golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2/go.mod h1:djNgcEr1/C05ACkg1iLfiJU5Ep61QUkGW8qpdssI0+w=
golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9/go.mod h1:LzIPMQfyMNhhGPhUkYOs5KpL4U8rLKemX1yGLhDgUto=
golang.org/x/crypto v0.25.0 h1:ypSNr+bnYL2YhwoMt2zPxHFmbAN1KZs/njMG3hxUp30=
golang.org/x/crypto v0.25.0/go.mod h1:T+wALwcMOSE0kXgUAnPAHqTLW+XHgcELELW8VaDgm/M=
golang.org/x/exp v0.0.0-20190121172915-509febef88a4/go.mod h1:CJ0aWSM057203Lf6IL+f9T1iT9GByDxfZKAQTCR3kQA=
golang.org/x/lint v0.0.0-20181026193005-c67002cb31c3/go.mod h1:UVdnD1Gm6xHRNCYTkRU2/jEulfH38KcIWyp/GAMgvoE=
golang.org/x/lint v0.0.0-20190227174305-5b3e6a55c961/go.mod h1:wehouNa3lNwaWXcvxsM5YxQ5yQlVC4a0KAMCusXpPoU=
golang.org/x/lint v0.0.0-20190313153728-d0100b6bd8b3/go.mod h1:6SW0HCj/g11FgYtHlgUYUwCkIfeOF89ocIRzGO/8vkc=
golang.org/x/net v0.0.0-20180724234803-3673e40ba225/go.mod h1:mL1N/T3taQHkDXs73rZJwtUhF3w3ftmwwsq0BUmARs4=
golang.org/x/net v0.0.0-20180826012351-8a410e7b638d/go.mod h1:mL1N/T3taQHkDXs73rZJwtUhF3w3ftmwwsq0BUmARs4=
golang.org/x/net v0.0.0-20190213061140-3a22650c66bd/go.mod h1:mL1N/T3taQHkDXs73rZJwtUhF3w3ftmwwsq0BUmARs4=
golang.org/x/net v0.0.0-20190311183353-d8887717615a/go.mod h1:t9HGtf8HONx5eT2rtn7q6eTqICYqUVnKs3thJo3Qplg=
golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3/go.mod h1:t9HGtf8HONx5eT2rtn7q6eTqICYqUVnKs3thJo3Qplg=
golang.org/x/net v0.0.0-20201110031124-69a78807bb2b/go.mod h1:sp8m0HH+o8qH0wwXwYZr8TS3Oi6o0r6Gce1SSxlDquU=
golang.org/x/net v0.27.0 h1:5K3Njcw06/l2y9vpGCSdcxWOYHOUk3dVNGDXN+FvAys=
golang.org/x/net v0.27.0/go.mod h1:dDi0PyhWNoiUOrAS8uXv/vnScO4wnHQO4mj9fn/RytE=
golang.org/x/oauth2 v0.0.0-20180821212333-d2e6202438be/go.mod h1:N/0e6XlmueqKjAGxoOufVs8QHGRruUQn6yWY3a++T0U=
golang.org/x/oauth2 v0.21.0 h1:tsimM75w1tF/uws5rbeHzIWxEqElMehnc+iW793zsZs=
golang.org/x/oauth2 v0.21.0/go.mod h1:XYTD2NtWslqkgxebSiOHnXEap4TF09sJSc7H1sXbhtI=
golang.org/x/sync v0.0.0-20180314180146-1d60e4601c6f/go.mod h1:RxMgew5VJxzue5/jJTE5uejpjVlOe/izrB70Jof72aM=
golang.org/x/sync v0.0.0-20181108010431-42b317875d0f/go.mod h1:RxMgew5VJxzue5/jJTE5uejpjVlOe/izrB70Jof72aM=
golang.org/x/sync v0.0.0-20190423024810-112230192c58/go.mod h1:RxMgew5VJxzue5/jJTE5uejpjVlOe/izrB70Jof72aM=
golang.org/x/sync v0.7.0 h1:YsImfSBoP9QPYL0xyKJPq0gcaJdG3rInoqxTWbfQu9M=
golang.org/x/sync v0.7.0/go.mod h1:Czt+wKu1gCyEFDUtn0jG5QVvpJ6rzVqr5aXyt9drQfk=
golang.org/x/sys v0.0.0-20180830151530-49385e6e1522/go.mod h1:STP8DvDyc/dI5b8T5hshtkjS+E42TnysNCUPdjciGhY=
golang.org/x/sys v0.0.0-20190215142949-d0b11bdaac8a/go.mod h1:STP8DvDyc/dI5b8T5hshtkjS+E42TnysNCUPdjciGhY=
golang.org/x/sys v0.0.0-20190412213103-97732733099d/go.mod h1:h1NjWce9XRLGQEsW7wpKNCjG9DtNlClVuFLEZdDNbEs=
golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f/go.mod h1:h1NjWce9XRLGQEsW7wpKNCjG9DtNlClVuFLEZdDNbEs=
golang.org/x/sys v0.0.0-20220811171246-fbc7d0a398ab/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.6.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.12.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.22.0 h1:RI27ohtqKCnwULzJLqkv897zojh5/DwS/ENaMzUOaWI=
golang.org/x/sys v0.22.0/go.mod h1:/VUhepiaJMQUp4+oa/7Zr1D23ma6VTLIYjOOTFZPUcA=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
golang.org/x/text v0.3.3/go.mod h1:5Zoc/QRtKVWzQhOtBMvqHzDpF6irO9z98xDceosuGiQ=
golang.org/x/text v0.16.0 h1:a94ExnEXNtEwYLGJSIUxnWoxoRz/ZcCsV63ROupILh4=
golang.org/x/text v0.16.0/go.mod h1:GhwF1Be+LQoKShO3cGOHzqOgRrGaYc9AvblQOmPVHnI=
golang.org/x/time v0.5.0 h1:o7cqy6amK/52YcAKIPlM3a+Fpj35zvRj2TP+e1xFSfk=
golang.org/x/time v0.5.0/go.mod h1:3BpzKBy/shNhVucY/MWOyx10tF3SFh9QdLuxbVysPQM=
golang.org/x/tools v0.0.0-20180917221912-90fa682c2a6e/go.mod h1:n7NCudcB/nEzxVGmLbDWY5pfWTLqBcC2KZ6jyYvM4mQ=
golang.org/x/tools v0.0.0-20190114222345-bf090417da8b/go.mod h1:n7NCudcB/nEzxVGmLbDWY5pfWTLqBcC2KZ6jyYvM4mQ=
golang.org/x/tools v0.0.0-20190226205152-f727befe758c/go.mod h1:9Yl7xja0Znq3iFh3HoIrodX9oNMXvdceNzlUR8zjMvY=
golang.org/x/tools v0.0.0-20190311212946-11955173bddd/go.mod h1:LCzVGOaR6xXOjkQ3onu1FJEFr0SW1gC7cKk1uF8kGRs=
golang.org/x/tools v0.0.0-20190524140312-2c0ae7006135/go.mod h1:RgjU9mgBXZiqYHBnxXauZ1Gv1EHHAz9KjViQ78xBX0Q=
golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543/go.mod h1:I/5z698sn9Ka8TeJc9MKroUUfqBBauWjQqLJ2OPfmY0=
google.golang.org/api v0.189.0 h1:equMo30LypAkdkLMBqfeIqtyAnlyig1JSZArl4XPwdI=
google.golang.org/api v0.189.0/go.mod h1:FLWGJKb0hb+pU2j+rJqwbnsF+ym+fQs73rbJ+KAUgy8=
google.golang.org/appengine v1.1.0/go.mod h1:EbEs0AVv82hx2wNQdGPgUI5lhzA/G0D9YwlJXL52JkM=
google.golang.org/appengine v1.4.0/go.mod h1:xpcJRLb0r/rnEns0DIKYYv+WjYCduHsrkT7/EB5XEv4=
google.golang.org/genproto v0.0.0-20180817151627-c66870c02cf8/go.mod h1:JiN7NxoALGmiZfu7CAH4rXhgtRTLTxftemlI0sWmxmc=
google.golang.org/genproto v0.0.0-20190819201941-24fa4b261c55/go.mod h1:DMBHOl98Agz4BDEuKkezgsaosCRResVns1a3J2ZsMNc=
google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013/go.mod h1:NbSheEEYHJ7i3ixzK3sjbqSGDJWnxyFXZblF3eUsNvo=
google.golang.org/genproto/googleapis/api v0.0.0-20240722135656-d784300faade h1:WxZOF2yayUHpHSbUE6NMzumUzBxYc3YGwo0YHnbzsJY=
google.golang.org/genproto/googleapis/api v0.0.0-20240722135656-d784300faade/go.mod h1:mw8MG/Qz5wfgYr6VqVCiZcHe/GJEfI+oGGDCohaVgB0=
google.golang.org/genproto/googleapis/rpc v0.0.0-20240722135656-d784300faade h1:oCRSWfwGXQsqlVdErcyTt4A93Y8fo0/9D4b1gnI++qo=
google.golang.org/genproto/googleapis/rpc v0.0.0-20240722135656-d784300faade/go.mod h1:Ue6ibwXGpU+dqIcODieyLOcgj7z8+IcskoNIgZxtrFY=
google.golang.org/grpc v1.19.0/go.mod h1:mqu4LbDTu4XGKhr4mRzUsmM4RtVoemTSY81AxZiDr8c=
google.golang.org/grpc v1.23.0/go.mod h1:Y5yQAOtifL1yxbo5wqy6BxZv8vAUGQwXBOALyacEbxg=
google.golang.org/grpc v1.25.1/go.mod h1:c3i+UQWmh7LiEpx4sFZnkU36qjEYZ0imhYfXVyQciAY=
google.golang.org/grpc v1.27.0/go.mod h1:qbnxyOmOxrQa7FizSgH+ReBfzJrCY1pSN7KXBS8abTk=
google.golang.org/grpc v1.33.2/go.mod h1:JMHMWHQWaTccqQQlmk3MJZS+GWXOdAesneDmEnv2fbc=
google.golang.org/grpc v1.65.0 h1:bs/cUb4lp1G5iImFFd3u5ixQzweKizoZJAwBNLR42lc=
google.golang.org/grpc v1.65.0/go.mod h1:WgYC2ypjlB0EiQi6wdKixMqukr6lBc0Vo+oOgjrM5ZQ=
google.golang.org/protobuf v0.0.0-20200109180630-ec00e32a8dfd/go.mod h1:DFci5gLYBciE7Vtevhsrf46CRTquxDuWsQurQQe4oz8=
google.golang.org/protobuf v0.0.0-20200221191635-4d8936d0db64/go.mod h1:kwYJMbMJ01Woi6D6+Kah6886xMZcty6N08ah7+eCXa0=
google.golang.org/protobuf v0.0.0-20200228230310-ab0ca4ff8a60/go.mod h1:cfTl7dwQJ+fmap5saPgwCLgHXTUD7jkjRqWcaiX5VyM=
google.golang.org/protobuf v1.20.1-0.20200309200217-e05f789c0967/go.mod h1:A+miEFZTKqfCUM6K7xSMQL9OKL/b6hQv+e19PK+JZNE=
google.golang.org/protobuf v1.21.0/go.mod h1:47Nbq4nVaFHyn7ilMalzfO3qCViNmqZ2kzikPIcrTAo=
google.golang.org/protobuf v1.22.0/go.mod h1:EGpADcykh3NcUnDUJcl1+ZksZNG86OlYog2l/sGQquU=
google.golang.org/protobuf v1.23.0/go.mod h1:EGpADcykh3NcUnDUJcl1+ZksZNG86OlYog2l/sGQquU=
google.golang.org/protobuf v1.23.1-0.20200526195155-81db48ad09cc/go.mod h1:EGpADcykh3NcUnDUJcl1+ZksZNG86OlYog2l/sGQquU=
google.golang.org/protobuf v1.25.0/go.mod h1:9JNX74DMeImyA3h4bdi1ymwjUzf21/xIlbajtzgsN7c=
google.golang.org/protobuf v1.34.2 h1:6xV6lTsCfpGD21XK49h7MhtcApnLqkfYgPcdHftf6hg=
google.golang.org/protobuf v1.34.2/go.mod h1:qYOHts0dSfpeUzUFpOMr/WGzszTmLH+DiWniOlNbLDw=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
honnef.co/go/tools v0.0.0-20190102054323-c2f93a96b099/go.mod h1:rf3lG4BRIbNafJWhAfAdb/ePZxsR/4RtNHQocxwk9r4=
honnef.co/go/tools v0.0.0-20190523083050-ea95bdfd59fc/go.mod h1:rf3lG4BRIbNafJWhAfAdb/ePZxsR/4RtNHQocxwk9r4=

```

`internal/config/config.go`:

```go
package config

import (
	_ "embed"
	"regexp"

	"github.com/BurntSushi/toml"
	"github.com/rs/zerolog/log"
)

//go:embed gitleaks.toml
var defaultRules string

// ViperConfig is a temporary struct to match the TOML structure for parsing.
type ViperConfig struct {
	Rules []struct {
		ID          string
		Description string
		Regex       string
		SecretGroup int
		Entropy     float64
		Keywords    []string
	}
}

type Rule struct {
	ID          string
	Description string
	Regex       *regexp.Regexp
	SecretGroup int
	Keywords    []string
	Entropy     float64
}

type Config struct {
	Rules []Rule
}

func Load() (*Config, error) {
	var vc ViperConfig
	if _, err := toml.Decode(defaultRules, &vc); err != nil {
		return nil, err
	}

	var cfg Config
	for _, vr := range vc.Rules {
		re, err := regexp.Compile(vr.Regex)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to compile regex for rule %s", vr.ID)
			continue
		}

		newRule := Rule{
			ID:          vr.ID,
			Description: vr.Description,
			Regex:       re,
			SecretGroup: vr.SecretGroup,
			Keywords:    vr.Keywords,
			Entropy:     vr.Entropy,
		}
		cfg.Rules = append(cfg.Rules, newRule)
	}

	return &cfg, nil
}

```

`internal/config/gitleaks.toml`:

```toml
[[rules]]
id = "aws-access-token"
description = "AWS Access Token"
regex = '''\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b'''
keywords = ["AKIA", "ASIA"]

[[rules]]
id = "github-pat"
description = "GitHub Personal Access Token"
regex = '''ghp_[0-9a-zA-Z]{36}'''
keywords = ["ghp_"]

[[rules]]
id = "slack-webhook-url"
description = "Slack Webhook"
regex = '''https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}'''
keywords = ["hooks.slack.com"]

[[rules]]
id = "private-key"
description = "Asymmetric Private Key"
regex = '''-----BEGIN (?:[A-Z\s]+) PRIVATE KEY-----'''
keywords = ["-----BEGIN"]

[[rules]]
id = "generic-api-key"
description = "Generic API Key"
regex = '''(?i)(key|api|token|secret|password)"?\s*[:=]\s*["']([0-9a-zA-Z\-_.=]{20,})["']'''
secretGroup = 2
entropy = 3.5
keywords = ["key", "api", "token", "secret", "password"]
```

`internal/genai/gemini.go`:

```go
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

```

`internal/scanner/scanner.go`:

```go
package scanner

import (
	"gitleaks-lite/internal/config"
	"strings"

	"github.com/gitleaks/go-gitdiff/gitdiff"
)

// Finding represents a secret that has been found.
type Finding struct {
	RuleID      string
	File        string
	StartLine   int
	Secret      string
	Commit      string
	Author      string
	Email       string
	Date        string
	Message     string
	CodeContext string
}

type Scanner struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Scanner {
	return &Scanner{cfg: cfg}
}

// Scan performs the detection on a single gitdiff file.
func (s *Scanner) Scan(file *gitdiff.File) []Finding {
	var findings []Finding
	if file == nil || file.PatchHeader == nil {
		return findings
	}

	for _, textFragment := range file.TextFragments {
		if textFragment == nil {
			continue
		}

		content := textFragment.Raw(gitdiff.OpAdd)
		lines := strings.Split(content, "\n")

		for i, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if strings.Contains(line, "gitleaks:allow") {
				continue
			}

			for _, rule := range s.cfg.Rules {
				matches := rule.Regex.FindAllStringSubmatch(line, -1)
				if matches == nil {
					continue
				}

				for _, match := range matches {
					secret := ""
					// Safely determine the secret.
					if len(match) > rule.SecretGroup {
						secret = match[rule.SecretGroup]
					}
					// If a specific group is requested but empty, or not set, use the full match.
					if secret == "" {
						secret = match[0]
					}
					if secret == "" {
						continue
					}

					start := i - 2
					if start < 0 {
						start = 0
					}
					end := i + 3
					if end > len(lines) {
						end = len(lines)
					}
					contextSnippet := strings.Join(lines[start:end], "\n")

					findings = append(findings, Finding{
						RuleID:      rule.ID,
						File:        file.NewName,
						StartLine:   int(textFragment.NewPosition) + i,
						Secret:      secret,
						Commit:      file.PatchHeader.SHA,
						Author:      file.PatchHeader.Author.Name,
						Email:       file.PatchHeader.Author.Email,
						Date:        file.PatchHeader.AuthorDate.String(),
						Message:     file.PatchHeader.Message(),
						CodeContext: contextSnippet,
					})
				}
			}
		}
	}
	return findings
}

```

`main.go`:

```go
package main

import (
	"gitleaks-lite/cmd"
	"os"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

```

`run_tests.sh`:

```sh
#!/bin/bash

# --- Self-sufficient PATH configuration ---
if ! command -v go &> /dev/null; then
    echo "[SETUP] 'go' command not found. Adding default Go path to environment..."
    export PATH=$PATH:/usr/local/go/bin
fi
if ! command -v go &> /dev/null; then
    echo "[ERROR] Could not find 'go' executable." >&2
    exit 1
fi

set -e

# --- Configuration ---
DOCKER_IMAGE_NAME="gitleaks-lite-test"
REPO_CLEAN_PATH="$(pwd)/testdata/repos/repo-clean"
REPO_SECRET_PATH="$(pwd)/testdata/repos/repo-with-secret"
REPO_FP_PATH="$(pwd)/testdata/repos/repo-with-false-positive"

# --- Helper Functions for Logging ---
info() { echo -e "\033[0;34m[INFO]\033[0m $1"; }
success() { echo -e "\033[0;32m[SUCCESS]\033[0m $1"; }
error() { echo -e "\033[0;31m[ERROR]\033[0m $1" >&2; exit 1; }

# --- Test Runner Logic ---

info "--- Phase 1: Linting and Formatting ---"
FMT_OUTPUT=$(go fmt ./...)
if [ -n "$FMT_OUTPUT" ]; then
    error "Go files are not formatted. Please run 'go fmt ./...'\nFiles changed:\n$FMT_OUTPUT"
fi
go vet ./...
success "Code is well-formatted and passes vet checks."

info "\n--- Phase 2: Building Test Docker Image ---"
docker build -t "$DOCKER_IMAGE_NAME" .
success "Docker image '$DOCKER_IMAGE_NAME' built successfully."

info "\n--- Phase 3: Running Integration Tests ---"

# --- REMOVED THE -u FLAG FROM ALL DOCKER COMMANDS ---
BASE_DOCKER_RUN="docker run --rm"

# Test 1: Clean Repo - Expect exit code 0
info "Running test on clean repository..."
set +e
output_clean=$($BASE_DOCKER_RUN -v "$REPO_CLEAN_PATH:/scan" "$DOCKER_IMAGE_NAME" git /scan 2>&1)
exit_code_clean=$?
set -e

if [ $exit_code_clean -ne 0 ]; then
    error "Expected exit code 0 for clean repo, but got $exit_code_clean. Output:\n$output_clean"
fi
if ! echo "$output_clean" | grep -q "No secrets found"; then
    error "Expected 'No secrets found' for clean repo. Output:\n$output_clean"
fi
success "Clean repository test passed."

# Test 2: Repo with Secret (Regex-Only) - Expect exit code 1
info "\nRunning test on repo with secret (regex-only)..."
set +e
output_secret=$($BASE_DOCKER_RUN -v "$REPO_SECRET_PATH:/scan" "$DOCKER_IMAGE_NAME" git /scan 2>&1)
exit_code_secret=$?
set -e

if [ $exit_code_secret -ne 1 ]; then
    error "Expected exit code 1 for repo with secret, but got $exit_code_secret. Output:\n$output_secret"
fi
if ! echo "$output_secret" | grep -q "github-pat"; then
    error "Expected finding for rule 'github-pat' was not found. Output:\n$output_secret"
fi
success "Repo with secret (regex-only) test passed."

# GenAI related tests
if [ -z "$GEMINI_API_KEY" ]; then
    info "\n--- Skipping GenAI tests: GEMINI_API_KEY not set ---"
else
    info "\nGEMINI_API_KEY found. Proceeding with GenAI integration tests."

    # Test 3: Repo with Secret (GenAI Mode) - Expect exit code 1
    info "Running test on repo with secret (GenAI mode)..."
    set +e
    output_secret_ai=$($BASE_DOCKER_RUN -v "$REPO_SECRET_PATH:/scan" -e GEMINI_API_KEY="$GEMINI_API_KEY" "$DOCKER_IMAGE_NAME" git /scan 2>&1)
    exit_code_secret_ai=$?
    set -e

    if [ $exit_code_secret_ai -ne 1 ]; then
        error "Expected exit code 1 for repo with secret (GenAI mode), but got $exit_code_secret_ai. Output:\n$output_secret_ai"
    fi
    if ! echo "$output_secret_ai" | grep -q "github-pat"; then
        error "Expected finding for 'github-pat' not found in GenAI mode. Output:\n$output_secret_ai"
    fi
    success "Repo with secret (GenAI mode) test passed (True Positive Confirmed)."

    # Test 4: Repo with False Positive (GenAI Mode) - Expect exit code 0
    info "\nRunning test on repo with false positive (GenAI mode)..."
    set +e
    output_fp_ai=$($BASE_DOCKER_RUN -v "$REPO_FP_PATH:/scan" -e GEMINI_API_KEY="$GEMINI_API_KEY" "$DOCKER_IMAGE_NAME" git /scan 2>&1)
    exit_code_fp_ai=$?
    set -e
    
    if [ $exit_code_fp_ai -ne 0 ]; then
        error "Expected exit code 0 for repo with false positive (GenAI mode), but got $exit_code_fp_ai. Output:\n$output_fp_ai"
    fi
    if ! echo "$output_fp_ai" | grep -q "No secrets found"; then
        error "Expected 'No secrets found' for false positive repo. Output:\n$output_fp_ai"
    fi
    success "Repo with false positive (GenAI mode) test passed (False Positive Filtered)."
fi

info "\n--- Phase 4: Cleaning up ---"
# docker rmi "$DOCKER_IMAGE_NAME"
# success "Test Docker image '$DOCKER_IMAGE_NAME' removed."

echo ""
success "✅ ✅ ✅ ALL TESTS PASSED! ✅ ✅ ✅"
```

`scan_all_repos.sh`:

```sh
#!/bin/bash

# --- Configuration ---
SCAN_DIRECTORY="/home/mdt/dev"
DOCKER_IMAGE="gitleaks-lite:latest"
USE_GEMINI=true
SCAN_TIMEOUT="2m" # Set a 2-minute timeout for each repository scan.

# --- Helper function for logging ---
info() {
    echo -e "\033[0;34m[INFO]\033[0m $1"
}

# --- Script Logic ---

# Step 1: Handle API Key securely at the very beginning.
if [ "$USE_GEMINI" = true ] && [ -z "$GEMINI_API_KEY" ]; then
    echo "GenAI validation is enabled, but GEMINI_API_KEY is not set."
    read -sp "Please enter your Gemini API Key (or press Enter to skip GenAI scans): " temp_api_key
    echo
    if [ -n "$temp_api_key" ]; then
        export GEMINI_API_KEY="$temp_api_key"
        info "GEMINI_API_KEY has been set for this session."
    else
        info "No API key provided. GenAI validation will be skipped."
        USE_GEMINI=false
    fi
fi

echo "--- Starting Gitleaks-Lite Scan on all repositories in $SCAN_DIRECTORY ---"
echo "--- Timeout per repository is set to $SCAN_TIMEOUT ---"

repos_with_findings=0
start_time=$SECONDS

# Step 2: Loop through directories and scan.
for dir in "$SCAN_DIRECTORY"/*/; do
    if [ -d "$dir" ]; then
        repo_path=$(realpath "$dir")
        repo_name=$(basename "$repo_path")

        if git -C "$repo_path" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
            echo ""
            echo "========================================================================"
            echo "Scanning repository: $repo_name"
            echo "========================================================================"

            docker_args=( "run" "--rm" "-v" "$repo_path:/scan" )

            if [ "$USE_GEMINI" = true ] && [ -n "$GEMINI_API_KEY" ]; then
                docker_args+=("-e" "GEMINI_API_KEY=$GEMINI_API_KEY")
            fi

            docker_args+=("$DOCKER_IMAGE" "git" "/scan")

            # Execute the command with a timeout. This simplified execution is more stable.
            # The output will appear when the command finishes or times out.
            if output=$(timeout --foreground "$SCAN_TIMEOUT" docker "${docker_args[@]}" 2>&1); then
                # Exit code 0 (success)
                echo "$output"
            else
                status=$?
                if [ $status -eq 124 ]; then
                    echo "❌ ERROR: Scan for $repo_name timed out after $SCAN_TIMEOUT."
                elif [ $status -eq 1 ]; then
                    echo "$output"
                    echo "🚨🚨🚨 WARNING: Secrets found in $repo_name 🚨🚨🚨"
                    repos_with_findings=$((repos_with_findings + 1))
                else
                    echo "❌ ERROR: Scan for $repo_name failed with an unexpected error (exit code $status)."
                    echo "--- Error Output ---"
                    echo "$output"
                    echo "--------------------"
                fi
            fi
        else
            echo "-> Skipping '$repo_name' (not a Git repository)"
        fi
    fi
done

end_time=$SECONDS
duration=$((end_time - start_time))

echo ""
echo "========================================================================"
echo "--- Scan Complete ---"
echo "Total execution time: $((duration / 60)) minutes and $((duration % 60)) seconds."
if [ $repos_with_findings -gt 0 ]; then
    echo "Total repositories with findings: $repos_with_findings"
    exit 1
else
    echo "✅ No secrets found in any repository."
fi
```

`testdata/repos/repo-clean/README.md`:

```md
This is a clean repository with no secrets.

```

`testdata/repos/repo-with-false-positive/examples.py`:

```py
# This is an example key for documentation purposes only.
# It is not a real production secret.
EXAMPLE_API_KEY = "key_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmN"

```

`testdata/repos/repo-with-secret/config.yml`:

```yml
api_key: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmN"

```