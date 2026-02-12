# X-Ray — Site Intelligence

A web-based reconnaissance tool that scans websites and surfaces security-relevant information. Built on Cloudflare Workers with a Python scanner container.

Enter a domain and get back WAF detection, technology fingerprinting, TLS/SSL analysis, DNS records, HTTP security headers, IP/ASN information, WHOIS data, and passive subdomain enumeration — all wrapped in a security score.

## Architecture

```
Browser → Cloudflare Worker (TypeScript)
              ├── Static frontend (HTML/JS/Tailwind)
              ├── D1 database (scan history)
              ├── R2 bucket (result archival)
              └── Container (Python/FastAPI)
                    ├── wafw00f   — WAF detection
                    ├── webtech   — technology fingerprinting
                    ├── sslyze    — TLS/SSL analysis
                    ├── dnsx      — DNS enumeration
                    ├── httpx     — HTTP header analysis
                    ├── subfinder — passive subdomain discovery
                    └── whois     — WHOIS lookups
```

## Tools

| Tool | Description | Repo |
|------|-------------|------|
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | Identifies and fingerprints Web Application Firewalls (WAFs) by sending HTTP probes and analyzing responses | [EnableSecurity/wafw00f](https://github.com/EnableSecurity/wafw00f) |
| [webtech](https://github.com/ShielderSec/webtech) | Detects technologies used by websites — frameworks, CMS, CDNs, analytics, and more | [ShielderSec/webtech](https://github.com/ShielderSec/webtech) |
| [SSLyze](https://github.com/nabla-c0d3/sslyze) | Analyzes TLS/SSL configuration — cipher suites, certificate chain, protocol support, and common misconfigurations | [nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze) |
| [dnsx](https://github.com/projectdiscovery/dnsx) | Fast multi-purpose DNS toolkit — resolves A, AAAA, MX, NS, TXT, CNAME, and other record types | [projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) |
| [httpx](https://github.com/projectdiscovery/httpx) | Probes HTTP servers and extracts response headers, status codes, and metadata | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery using certificate transparency logs, search engines, and other OSINT sources | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |

## How the Container Works

The scanner runs inside a [Cloudflare Container](https://developers.cloudflare.com/containers/) — a Docker-based compute environment that runs alongside your Worker. The container is built with a multi-stage Dockerfile:

1. **Stage 1 (Go builder)** — compiles `dnsx`, `httpx`, and `subfinder` from source as static binaries
2. **Stage 2 (Python runtime)** — installs the Python tools (`wafw00f`, `webtech`, `sslyze`) via pip, copies the Go binaries in, and runs a FastAPI server on port 8080

When a scan is requested, the Worker picks a container instance from a pool of up to 5 (routed by target hash) and sends a POST to `/scan`. The container runs all 7 tools concurrently as subprocesses with a 60s per-tool timeout and a 120s total timeout. Partial results are preserved if individual tools fail or time out.

The container sleeps after 5 minutes of inactivity and wakes automatically on the next request.

## Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) (v4+)
- A Cloudflare account with [Containers](https://developers.cloudflare.com/containers/) enabled

## Setup

1. **Clone and install dependencies:**

   ```sh
   git clone https://github.com/brenobra/xray.git
   cd xray
   npm install
   ```

2. **Configure `wrangler.jsonc`:**

   Replace the placeholder values with your own:
   - `account_id` — your Cloudflare account ID
   - `database_id` — your D1 database ID (created in the next step)
   - `ALLOWED_ORIGIN` — the domain where your frontend is served (for CORS)

3. **Create the D1 database and apply the schema:**

   ```sh
   npm run db:create
   npm run db:migrate
   ```

4. **Create the R2 bucket:**

   ```sh
   wrangler r2 bucket create site-intelligence-archive
   ```

## Development

```sh
npm run dev
```

This starts a local Wrangler dev server with the Worker and container.

## Deploy

```sh
npm run deploy
```

## License

[MIT](LICENSE)
