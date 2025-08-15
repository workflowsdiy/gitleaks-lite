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