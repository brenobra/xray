"""Parser for SSLyze — TLS/SSL configuration analysis."""

import json
from urllib.parse import urlparse
from typing import Any


def build_command(target: str) -> list[str]:
    parsed = urlparse(target)
    host = parsed.hostname or target
    port = parsed.port or 443
    return ["python", "-m", "sslyze", "--json_out=-", f"{host}:{port}"]


def parse_output(stdout: str, stderr: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "protocols": [],
        "cipher_suites": [],
        "certificate": {"issuer": "", "expiry": "", "san": []},
    }

    try:
        data = json.loads(stdout)
        server_results = data.get("server_scan_results", [])
        if not server_results:
            return result

        scan = server_results[0]
        commands = scan.get("scan_result", {})

        # Extract supported TLS protocols
        protocol_map = {
            "tls_1_0_cipher_suites": "TLSv1.0",
            "tls_1_1_cipher_suites": "TLSv1.1",
            "tls_1_2_cipher_suites": "TLSv1.2",
            "tls_1_3_cipher_suites": "TLSv1.3",
        }

        for field_key, proto_name in protocol_map.items():
            proto_data = commands.get(field_key, {})
            accepted = proto_data.get("result", {}).get("accepted_cipher_suites", [])
            if accepted:
                result["protocols"].append(proto_name)
                for cs in accepted:
                    suite_name = cs.get("cipher_suite", {}).get("name", "")
                    if suite_name and suite_name not in result["cipher_suites"]:
                        result["cipher_suites"].append(suite_name)

        # Extract certificate info
        cert_info = commands.get("certificate_info", {}).get("result", {})
        deployments = cert_info.get("certificate_deployments", [])
        if deployments:
            leaf_chain = deployments[0].get("received_certificate_chain", [])
            if leaf_chain:
                leaf = leaf_chain[0]
                result["certificate"]["issuer"] = str(leaf.get("issuer", {}).get("rfc4514_string", ""))
                result["certificate"]["expiry"] = str(leaf.get("not_valid_after", ""))
                san = leaf.get("subject_alternative_name", {})
                result["certificate"]["san"] = san.get("dns", [])
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        if stderr:
            result["_error"] = stderr[:500]

    return result
