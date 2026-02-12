# =============================================================================
# Stage 1: Build Go binaries (ProjectDiscovery tools)
# =============================================================================
FROM golang:1.24-alpine AS go-builder

RUN apk add --no-cache git

# Build dnsx — fast DNS resolver with CDN detection
RUN CGO_ENABLED=0 go install -ldflags="-s -w" -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Build httpx — HTTP probe with tech detection and header extraction
RUN CGO_ENABLED=0 go install -ldflags="-s -w" -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Build subfinder — passive subdomain enumeration
RUN CGO_ENABLED=0 go install -ldflags="-s -w" -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# =============================================================================
# Stage 2: Python application with recon tools
# =============================================================================
FROM python:3.12-slim

# Install system deps needed by sslyze (OpenSSL) and DNS tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl-dev \
        dnsutils \
        whois \
    && rm -rf /var/lib/apt/lists/*

# Copy Go binaries from builder (stripped, ~30MB each)
COPY --from=go-builder /go/bin/dnsx /usr/local/bin/dnsx
COPY --from=go-builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/subfinder

WORKDIR /app

# Install Python dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Required for local dev with wrangler
EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
