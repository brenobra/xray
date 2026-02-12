"""Parser for webtech — technology stack detection via Wappalyzer rules."""

import json
from typing import Any


def build_command(target: str) -> list[str]:
    return ["webtech", "-u", target]


def parse_output(stdout: str, stderr: str) -> list[dict[str, Any]]:
    technologies: list[dict[str, Any]] = []

    try:
        data = json.loads(stdout)
        tech_list = data.get("tech", [])
        # webtech may return tech as a list of dicts or a dict
        if isinstance(tech_list, dict):
            for name, info in tech_list.items():
                technologies.append({
                    "name": name,
                    "category": info.get("category", "Unknown") if isinstance(info, dict) else "Unknown",
                    "version": info.get("version") if isinstance(info, dict) else None,
                    "confidence": info.get("confidence") if isinstance(info, dict) else None,
                })
        elif isinstance(tech_list, list):
            for item in tech_list:
                if isinstance(item, dict):
                    technologies.append({
                        "name": item.get("name", "Unknown"),
                        "category": item.get("category", "Unknown"),
                        "version": item.get("version"),
                        "confidence": item.get("confidence"),
                    })
                elif isinstance(item, str):
                    technologies.append({
                        "name": item,
                        "category": "Unknown",
                        "version": None,
                        "confidence": None,
                    })
    except (json.JSONDecodeError, KeyError, AttributeError):
        # Fallback: try line-by-line parsing of non-JSON output
        for line in stdout.strip().splitlines():
            line = line.strip("- \t")
            if line and not line.startswith(("{", "[", "Target", "http")):
                technologies.append({
                    "name": line,
                    "category": "Unknown",
                    "version": None,
                    "confidence": None,
                })

    return technologies
