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