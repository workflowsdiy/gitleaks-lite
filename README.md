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