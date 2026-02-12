"""Parser for wafw00f — WAF detection and fingerprinting."""

import json
from typing import Any

COMMAND = ["wafw00f", "-a", "-o-", "-f", "json"]


def build_command(target: str) -> list[str]:
    return COMMAND + [target]


def parse_output(stdout: str, stderr: str) -> dict[str, Any]:
    try:
        data = json.loads(stdout)
        if isinstance(data, list) and len(data) > 0:
            entry = data[0]
            firewall = entry.get("firewall", "")
            detected = bool(firewall) and firewall.lower() not in ("", "none", "generic")
            return {
                "detected": detected,
                "provider": firewall if detected else None,
                "details": entry,
            }
    except (json.JSONDecodeError, IndexError, KeyError):
        pass

    return {"detected": False, "provider": None, "details": {"raw_stderr": stderr[:500]}}
