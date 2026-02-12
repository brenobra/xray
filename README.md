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
| [webtech](https://github.com/nicksahler/webtech) | Detects technologies used by websites — frameworks, CMS, CDNs, analytics, and more | [nicksahler/webtech](https://github.com/nicksahler/webtech) |
| [SSLyze](https://github.com/nabla-c0d3/sslyze) | Analyzes TLS/SSL configuration — cipher suites, certificate chain, protocol support, and common misconfigurations | [nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze) |
| [dnsx](https://github.com/projectdiscovery/dnsx) | Fast multi-purpose DNS toolkit — resolves A, AAAA, MX, NS, TXT, CNAME, and other record types | [projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) |
| [httpx](https://github.com/projectdiscovery/httpx) | Probes HTTP servers and extracts response headers, status codes, and metadata | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery using certificate transparency logs, search engines, and other OSINT sources | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |

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
