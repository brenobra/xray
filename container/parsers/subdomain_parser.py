"""Parser for subfinder (ProjectDiscovery) — passive subdomain enumeration."""

import json
from urllib.parse import urlparse
from typing import Any


def build_command(target: str) -> list[str]:
    parsed = urlparse(target)
    host = parsed.hostname or target
    # Extract the registrable domain for subdomain enumeration
    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    return ["subfinder", "-d", domain, "-json", "-silent"]


def parse_output(stdout: str, stderr: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "subdomains": [],
        "sources": {},
        "count": 0,
    }

    if not stdout.strip():
        return result

    seen = set()
    for line in stdout.strip().splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "").strip().lower()
            source = data.get("source", "unknown")
            if host and host not in seen:
                seen.add(host)
                result["subdomains"].append(host)
                result["sources"][host] = source
        except (json.JSONDecodeError, KeyError, TypeError):
            # Fallback: some versions just output one hostname per line
            host = line.strip().lower()
            if host and host not in seen and "." in host:
                seen.add(host)
                result["subdomains"].append(host)

    result["subdomains"].sort()
    result["count"] = len(result["subdomains"])
    return result
