"""Parser for httpx (ProjectDiscovery) — HTTP probing and header analysis."""

import json
import shlex
from urllib.parse import urlparse
from typing import Any

SECURITY_HEADER_KEYS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]


def build_command(target: str) -> list[str]:
    parsed = urlparse(target)
    host = parsed.hostname or target
    scheme = parsed.scheme or "https"
    url = f"{scheme}://{host}"
    safe_url = shlex.quote(url)
    return [
        "sh", "-c",
        f"echo {safe_url} | httpx -json -silent -title -server -tech-detect -status-code -follow-redirects -include-response-header",
    ]


def _parse_raw_headers(raw: str) -> dict[str, str]:
    """Parse raw HTTP response header string into a lowercase dict."""
    headers: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("HTTP/"):
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            # If duplicate header, append with semicolon
            if key in headers:
                headers[key] = headers[key] + "; " + value
            else:
                headers[key] = value
    return headers


def parse_output(stdout: str, stderr: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "server": "",
        "security_headers": {k: "missing" for k in SECURITY_HEADER_KEYS},
        "all_headers": {},
    }

    technologies_from_httpx: list[dict[str, Any]] = []

    try:
        for line in stdout.strip().splitlines():
            if not line.strip():
                continue
            data = json.loads(line)

            # httpx outputs response headers as a raw string in "response_header"
            # when -include-response-header is used
            raw_header_str = data.get("response_header", "") or ""
            headers = _parse_raw_headers(raw_header_str)

            # Fallback: if httpx returns a parsed dict in "header"
            if not headers:
                raw_dict = data.get("header", {}) or {}
                if isinstance(raw_dict, dict):
                    for k, v in raw_dict.items():
                        if isinstance(v, list):
                            headers[k.lower()] = "; ".join(v)
                        else:
                            headers[k.lower()] = str(v)

            result["server"] = data.get("webserver", "") or headers.get("server", "")
            result["all_headers"] = headers

            # Check security headers — httpx may use underscores (content_type)
            # or hyphens (content-type), so check both forms
            for key in SECURITY_HEADER_KEYS:
                underscore_key = key.replace("-", "_")
                val = headers.get(key, "") or headers.get(underscore_key, "")
                result["security_headers"][key] = "present" if val else "missing"

            # Extract tech detections from httpx if available
            techs = data.get("tech", []) or []
            for t in techs:
                if isinstance(t, str):
                    technologies_from_httpx.append({
                        "name": t,
                        "category": "Unknown",
                        "version": None,
                        "confidence": None,
                    })

            break  # process first JSON line only
    except (json.JSONDecodeError, KeyError, TypeError):
        if stderr:
            result["_error"] = stderr[:500]

    # Attach extra tech detections for the orchestrator to merge
    if technologies_from_httpx:
        result["_extra_technologies"] = technologies_from_httpx

    return result
