"""FastAPI server — exposes /scan and /health endpoints on port 8080."""

import re
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator

from scanner import run_scan

app = FastAPI(title="Site Intelligence Scanner", version="1.0.0")

# Strict hostname regex: alphanumeric, hyphens, dots only (prevents shell injection)
HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)

BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal"}
BLOCKED_HOSTNAME_SUFFIXES = (".localhost", ".internal")


def _is_blocked_hostname(hostname: str) -> bool:
    lower = hostname.lower()
    if lower in BLOCKED_HOSTNAMES:
        return True
    return any(lower.endswith(s) for s in BLOCKED_HOSTNAME_SUFFIXES)


class ScanRequest(BaseModel):
    target: str

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target URL cannot be empty")

        # Add scheme if missing
        if not v.startswith(("http://", "https://")):
            v = f"https://{v}"

        parsed = urlparse(v)
        if not parsed.hostname:
            raise ValueError("Invalid URL: no hostname found")

        if not HOSTNAME_RE.match(parsed.hostname):
            raise ValueError("Invalid hostname format")

        if _is_blocked_hostname(parsed.hostname):
            raise ValueError("Scanning internal or reserved hostnames is not allowed")

        return v


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "site-intelligence-scanner"}


@app.post("/scan")
async def scan(request: ScanRequest) -> dict:
    try:
        result = await run_scan(request.target)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
