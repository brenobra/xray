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

## Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) (v4+)
- A Cloudflare account with [Containers](https://developers.cloudflare.com/containers/) enabled

## Setup

1. **Clone and install dependencies:**

   ```sh
   git clone https://github.com/<your-username>/site-intelligence.git
   cd site-intelligence
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
