#!/bin/bash

# --- Configuration ---
SCAN_DIRECTORY="/home/mdt/dev"
DOCKER_IMAGE="gitleaks-lite:latest"
USE_GEMINI=true
# Set a timeout in seconds for each repository scan.
# '10m' for 10 minutes, '1h' for 1 hour, etc.
SCAN_TIMEOUT="2m"

if [ -z "$GEMINI_API_KEY" ]; then
    if [ "$USE_GEMINI" = true ]; then
        echo "GEMINI_API_KEY environment variable is not set."
        read -sp "Please enter your Gemini API Key: " GEMINI_API_KEY
        echo
        export GEMINI_API_KEY
    fi
fi
# --- End Configuration ---


# --- Script Logic ---
echo "--- Starting Gitleaks-Lite Scan on all repositories in $SCAN_DIRECTORY ---"
echo "--- Timeout per repository is set to $SCAN_TIMEOUT ---"

repos_with_findings=0
start_time=$SECONDS

# Find all directories inside the scan directory
for dir in "$SCAN_DIRECTORY"/*/; do
    # Check if it's a directory and contains a .git folder
    if [ -d "${dir}.git" ]; then
        repo_path=$(realpath "$dir")
        repo_name=$(basename "$repo_path")

        echo ""
        echo "========================================================================"
        echo "Scanning repository: $repo_name"
        echo "Path: $repo_path"
        echo "========================================================================"

        DOCKER_CMD="docker run --rm -v \"$repo_path:/scan\""

        if [ "$USE_GEMINI" = true ]; then
            if [ -z "$GEMINI_API_KEY" ]; then
                echo "Skipping GenAI validation for $repo_name as API key is not available."
                DOCKER_CMD="$DOCKER_CMD $DOCKER_IMAGE git /scan"
            else
                DOCKER_CMD="$DOCKER_CMD -e GEMINI_API_KEY=\"$GEMINI_API_KEY\" $DOCKER_IMAGE git /scan"
            fi
        else
            DOCKER_CMD="$DOCKER_CMD $DOCKER_IMAGE git /scan"
        fi

        # NEW: Execute the command with a timeout
        # 'timeout' is a standard Linux utility.
        # We capture the exit code of the timeout command itself.
        timeout --foreground "$SCAN_TIMEOUT" bash -c "$DOCKER_CMD" > >(tee /dev/tty) 2>&1
        # The exit status of the pipeline is the status of the last command to exit with a non-zero status
        # We need to get the exit code of the timeout command.
        status=${PIPESTATUS[0]}

        # Interpret the exit code
        if [ $status -eq 124 ]; then
            # Exit code 124 means the command timed out
            echo "❌ ERROR: Scan for $repo_name timed out after $SCAN_TIMEOUT."
        elif [ $status -eq 1 ]; then
            # Exit code 1 from our script means secrets were found
            echo "🚨🚨🚨 WARNING: Secrets found in $repo_name 🚨🚨🚨"
            repos_with_findings=$((repos_with_findings + 1))
        elif [ $status -ne 0 ]; then
            # Any other non-zero exit code is an unexpected error
            echo "❌ ERROR: Scan for $repo_name failed with exit code $status."
        fi

    else
        echo "-> Skipping '$(basename "$dir")' (not a Git repository)"
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