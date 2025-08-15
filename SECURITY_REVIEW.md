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