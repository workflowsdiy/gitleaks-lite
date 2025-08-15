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