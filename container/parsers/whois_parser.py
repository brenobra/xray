"""Parser for whois — domain registration information."""

import re
from urllib.parse import urlparse
from typing import Any


def build_command(target: str) -> list[str]:
    parsed = urlparse(target)
    host = parsed.hostname or target
    # Extract the registrable domain (last two parts) for WHOIS
    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    return ["whois", domain]


def parse_output(stdout: str, stderr: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "registrar": "",
        "creation_date": "",
        "expiry_date": "",
        "updated_date": "",
        "nameservers": [],
        "registrant_org": "",
        "status": [],
    }

    if not stdout.strip():
        return result

    lines = stdout.strip().splitlines()

    # Common WHOIS field patterns (case-insensitive)
    patterns = {
        "registrar": [
            r"(?i)registrar\s*:\s*(.+)",
            r"(?i)registrar name\s*:\s*(.+)",
            r"(?i)sponsoring registrar\s*:\s*(.+)",
        ],
        "creation_date": [
            r"(?i)creat(?:ion|ed)\s*date\s*:\s*(.+)",
            r"(?i)registration\s*date\s*:\s*(.+)",
        ],
        "expiry_date": [
            r"(?i)(?:registry\s*)?expir(?:y|ation)\s*date\s*:\s*(.+)",
            r"(?i)paid-till\s*:\s*(.+)",
        ],
        "updated_date": [
            r"(?i)updated?\s*date\s*:\s*(.+)",
            r"(?i)last[\s-]*(?:updated?|modified)\s*:\s*(.+)",
        ],
        "registrant_org": [
            r"(?i)registrant\s*organi[sz]ation\s*:\s*(.+)",
            r"(?i)registrant\s*:\s*(.+)",
            r"(?i)org(?:anization)?\s*:\s*(.+)",
        ],
    }

    for line in lines:
        line = line.strip()
        if not line or line.startswith("%") or line.startswith("#"):
            continue

        for field, regexes in patterns.items():
            if result[field]:
                continue
            for regex in regexes:
                match = re.match(regex, line)
                if match:
                    result[field] = match.group(1).strip()
                    break

        # Nameservers
        ns_match = re.match(r"(?i)name\s*server\s*:\s*(.+)", line)
        if ns_match:
            ns = ns_match.group(1).strip().lower().rstrip(".")
            if ns and ns not in result["nameservers"]:
                result["nameservers"].append(ns)

        # Domain status
        status_match = re.match(r"(?i)(?:domain\s*)?status\s*:\s*(.+)", line)
        if status_match:
            s = status_match.group(1).strip().split()[0]  # Take first word (e.g., clientTransferProhibited)
            if s and s not in result["status"] and len(result["status"]) < 10:
                result["status"].append(s)

    return result
