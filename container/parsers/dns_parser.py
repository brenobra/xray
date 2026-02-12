"""Parser for dnsx (ProjectDiscovery) — DNS resolution and CDN detection."""

import json
import shlex
from urllib.parse import urlparse
from typing import Any


def build_command(target: str) -> list[str]:
    parsed = urlparse(target)
    host = parsed.hostname or target
    safe_host = shlex.quote(host)
    return [
        "sh", "-c",
        f"echo {safe_host} | dnsx -json -a -cname -ns -mx -resp -cdn -asn -silent",
    ]


def parse_output(stdout: str, stderr: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "a_records": [],
        "cname_records": [],
        "ns_records": [],
        "mx_records": [],
        "cdn_detected": "",
        "hosting_provider": "",
    }

    try:
        for line in stdout.strip().splitlines():
            if not line.strip():
                continue
            data = json.loads(line)

            result["a_records"] = data.get("a", []) or []
            result["cname_records"] = data.get("cname", []) or []
            result["ns_records"] = data.get("ns", []) or []
            result["mx_records"] = data.get("mx", []) or []
            result["cdn_detected"] = data.get("cdn_name", "") or ""

            if data.get("asn"):
                asn_info = data["asn"]
                result["hosting_provider"] = asn_info.get("as_org", "") or ""
                result["asn"] = asn_info.get("as_number", "") or ""
            break  # dnsx outputs one JSON line per host
    except (json.JSONDecodeError, KeyError, TypeError):
        if stderr:
            result["_error"] = stderr[:500]

    return result
