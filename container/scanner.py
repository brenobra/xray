"""Scan orchestrator — runs all recon tools concurrently and returns unified results."""

import asyncio
import re
import time
from typing import Any

from parsers import (
    wafw00f_parser,
    webtech_parser,
    sslyze_parser,
    dns_parser,
    headers_parser,
    whois_parser,
    subdomain_parser,
)

TOOL_TIMEOUT = 60  # seconds per tool
TOTAL_TIMEOUT = 120  # seconds for entire scan

# Registry: key = unified schema section name, value = parser module
TOOLS: dict[str, Any] = {
    "waf": wafw00f_parser,
    "technologies": webtech_parser,
    "tls": sslyze_parser,
    "dns": dns_parser,
    "headers": headers_parser,
    "whois": whois_parser,
    "subdomains": subdomain_parser,
}


async def run_tool(name: str, module: Any, target: str) -> tuple[str, Any, str | None]:
    """Run a single recon tool as a subprocess with timeout.

    Returns (tool_name, parsed_result_or_None, error_message_or_None).
    """
    cmd = module.build_command(target)

    try:
        if isinstance(cmd, list) and len(cmd) >= 3 and cmd[0] == "sh" and cmd[1] == "-c":
            proc = await asyncio.create_subprocess_shell(
                cmd[2],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=TOOL_TIMEOUT
        )

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        result = module.parse_output(stdout, stderr)
        return (name, result, None)

    except asyncio.TimeoutError:
        try:
            proc.kill()  # type: ignore[possibly-undefined]
            await proc.wait()  # type: ignore[possibly-undefined]
        except Exception:
            pass
        return (name, None, f"{name} timed out after {TOOL_TIMEOUT}s")

    except Exception as e:
        return (name, None, f"{name} failed: {str(e)}")


async def _lookup_asn(ip: str) -> tuple[str, str]:
    """Look up ASN info for an IP using ipapi.co (free, HTTPS).

    Returns (asn_string, org_name). Falls back to ("", "") on failure.
    """
    try:
        import urllib.request
        import json

        # Validate IP format to prevent injection
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            return ("", "")

        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": "site-intelligence/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())

        asn = data.get("asn", "")
        org = data.get("org", "")
        return (asn, org)
    except Exception:
        return ("", "")


async def run_scan(target: str) -> dict[str, Any]:
    """Run all recon tools concurrently and return the unified report."""
    start_time = time.time()

    async_tasks = [
        asyncio.create_task(run_tool(name, module, target))
        for name, module in TOOLS.items()
    ]

    # Wait with total timeout — preserves partial results from completed tools
    done, pending = await asyncio.wait(async_tasks, timeout=TOTAL_TIMEOUT)

    for task in pending:
        task.cancel()

    completed: list[Any] = []
    for task in done:
        exc = task.exception()
        if exc is not None:
            completed.append(exc)
        else:
            completed.append(task.result())

    if pending:
        completed.append(
            ("_timeout", None, f"Total scan timeout ({TOTAL_TIMEOUT}s) — {len(pending)} tool(s) still running")
        )

    # Build unified response with safe defaults
    scan_result: dict[str, Any] = {
        "target": target,
        "scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "waf": {"detected": False, "provider": None, "details": {}},
        "technologies": [],
        "tls": {
            "protocols": [],
            "cipher_suites": [],
            "certificate": {"issuer": "", "expiry": "", "san": []},
        },
        "dns": {
            "a_records": [],
            "cname_records": [],
            "ns_records": [],
            "mx_records": [],
            "cdn_detected": "",
            "hosting_provider": "",
        },
        "headers": {
            "server": "",
            "security_headers": {},
            "all_headers": {},
        },
        "ip_info": {"ip": "", "asn": "", "org": ""},
        "whois": {
            "registrar": "",
            "creation_date": "",
            "expiry_date": "",
            "updated_date": "",
            "nameservers": [],
            "registrant_org": "",
            "status": [],
        },
        "subdomains": {"subdomains": [], "sources": {}, "count": 0},
        "errors": [],
        "duration_ms": 0,
    }

    for item in completed:
        if isinstance(item, BaseException):
            scan_result["errors"].append(str(item))
            continue

        name, result, error = item
        if error:
            scan_result["errors"].append(error)
        if result is not None:
            scan_result[name] = result

    # Merge any extra tech detections from httpx into the technologies list
    headers_data = scan_result.get("headers", {})
    extra_techs = headers_data.pop("_extra_technologies", [])
    if extra_techs:
        existing_names = {t["name"].lower() for t in scan_result["technologies"]}
        for tech in extra_techs:
            if tech["name"].lower() not in existing_names:
                scan_result["technologies"].append(tech)

    # Populate ip_info from DNS results
    dns_data = scan_result.get("dns", {})
    a_records = dns_data.get("a_records", [])
    if a_records:
        scan_result["ip_info"]["ip"] = a_records[0]

    # Use dnsx ASN data if available, otherwise do a Team Cymru DNS lookup
    asn = dns_data.get("asn", "")
    org = dns_data.get("hosting_provider", "")
    if a_records and (not asn or not org):
        cymru_asn, cymru_org = await _lookup_asn(a_records[0])
        if not asn:
            asn = cymru_asn
        if not org:
            org = cymru_org
    scan_result["ip_info"]["asn"] = asn
    scan_result["ip_info"]["org"] = org

    scan_result["duration_ms"] = int((time.time() - start_time) * 1000)
    return scan_result
