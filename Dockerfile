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

# THIS IS THE NEW LINE
# Mark any directory mounted into the container as safe for Git operations.
# This resolves ownership issues when mounting volumes.
RUN git config --global --add safe.directory '*'

# Copy the binary from the builder stage
COPY --from=builder /app/gitleaks-lite /usr/local/bin/gitleaks-lite

# Set the entrypoint for the container
ENTRYPOINT ["gitleaks-lite"]

# The default command can be to show help
CMD ["--help"]