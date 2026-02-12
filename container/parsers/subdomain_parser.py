"""Parser for subfinder (ProjectDiscovery) — passive subdomain enumeration."""

import json
import re
from collections import Counter, defaultdict
from urllib.parse import urlparse
from typing import Any


# ---------------------------------------------------------------------------
# CF-aware subdomain classification
# ---------------------------------------------------------------------------

# Each category: (name, cf_opportunity, interest, keywords)
CATEGORIES = [
    (
        "Competitor / Vendor",
        "Direct competitive displacement",
        "high",
        [
            "akamai", "fastly", "cloudfront", "incapsula", "imperva", "sucuri",
            "stackpath", "maxcdn", "keycdn", "bunnycdn", "limelight", "edgecast",
            "azure", "aws", "gcp", "heroku", "vercel", "netlify",
            "f5", "citrix", "zscaler", "paloalto", "fortinet",
        ],
    ),
    (
        "CDN & Performance",
        "CF CDN, R2, Images, Stream",
        "high",
        ["cdn", "static", "assets", "cache", "edge", "content", "img", "images", "media", "stream", "video"],
    ),
    (
        "Network Access",
        "CF Zero Trust (ZTNA, Access, Gateway, Tunnel)",
        "high",
        ["vpn", "ztna", "access", "tunnel", "gateway", "proxy", "swg", "remote", "connect"],
    ),
    (
        "Email",
        "CF Email Security, Email Routing",
        "high",
        ["mail", "smtp", "imap", "pop", "mx", "email", "webmail", "postfix", "exchange", "outlook"],
    ),
    (
        "Security",
        "CF Application Security (WAF, DDoS, Bot Mgmt)",
        "high",
        ["waf", "ddos", "firewall", "shield", "security", "bot", "captcha", "protect"],
    ),
    (
        "DNS",
        "CF Authoritative DNS",
        "medium",
        ["ns", "ns1", "ns2", "dns", "resolver", "nameserver"],
    ),
    (
        "Auth & Identity",
        "CF Access (Zero Trust identity)",
        "medium",
        ["sso", "oauth", "auth", "login", "identity", "idp", "saml", "adfs", "okta", "duo", "ping"],
    ),
    (
        "API & Compute",
        "CF Workers, API Shield",
        "medium",
        ["api", "graphql", "gateway", "rest", "ws", "lambda", "function", "serverless", "worker"],
    ),
    (
        "Storage & Hosting",
        "CF R2, Pages",
        "medium",
        ["storage", "s3", "blob", "bucket", "hosting", "sites", "pages", "upload"],
    ),
    (
        "Internal Tools",
        "CF Access (secure internal apps), Pages",
        "low",
        [
            "admin", "portal", "dashboard", "jira", "confluence", "jenkins",
            "gitlab", "grafana", "kibana", "sentry", "vault",
            "staging", "dev", "test", "uat", "preprod", "sandbox",
        ],
    ),
]

DEFAULT_CATEGORY = ("Standard", "General", "low")


def _classify_one(subdomain: str, base_domain: str) -> tuple[str, str, str]:
    """Return (category, cf_opportunity, interest) for a single subdomain."""
    # Strip the base domain to get just the prefix labels
    prefix = subdomain
    if subdomain.endswith("." + base_domain):
        prefix = subdomain[: -(len(base_domain) + 1)]

    labels = prefix.lower().replace("-", ".").replace("_", ".").split(".")

    for cat_name, cf_opp, interest, keywords in CATEGORIES:
        for kw in keywords:
            for label in labels:
                if kw == label or kw in label:
                    return cat_name, cf_opp, interest
    return DEFAULT_CATEGORY


def _detect_groups(classified: list[dict], base_domain: str, min_group: int = 3) -> list[dict]:
    """Find prefix clusters: 3+ subdomains sharing a common prefix pattern."""
    groups: list[dict] = []

    # Bucket subdomains by category, then by second-level prefix
    by_category: dict[str, list[dict]] = defaultdict(list)
    for item in classified:
        by_category[item["category"]].append(item)

    for category, items in by_category.items():
        # Extract the "stem" of each subdomain: strip trailing digits/hyphens
        stems: dict[str, list[dict]] = defaultdict(list)
        for item in items:
            sub = item["subdomain"]
            prefix = sub
            if sub.endswith("." + base_domain):
                prefix = sub[: -(len(base_domain) + 1)]
            # Collapse trailing digits to create a stem  e.g. node-1 -> node-*
            stem = re.sub(r"[\d]+", "*", prefix)
            if stem != prefix:  # Only group if there was a numeric component
                stems[stem].append(item)

        for stem, members in stems.items():
            if len(members) >= min_group:
                groups.append({
                    "prefix": stem + "." + base_domain,
                    "count": len(members),
                    "category": category,
                    "members": [m["subdomain"] for m in members],
                })

    return groups


def classify_subdomains(
    subdomains: list[str],
    sources: dict[str, str],
    base_domain: str,
) -> dict[str, Any]:
    """Classify subdomains into CF-relevant categories with interest scoring."""
    classified: list[dict] = []
    cat_counts: dict[str, int] = Counter()

    interest_order = {"high": 0, "medium": 1, "low": 2}

    for sub in subdomains:
        cat_name, cf_opp, interest = _classify_one(sub, base_domain)
        classified.append({
            "subdomain": sub,
            "category": cat_name,
            "interest": interest,
            "cf_opportunity": cf_opp,
            "source": sources.get(sub, "unknown"),
        })
        cat_counts[cat_name] += 1

    # Sort by interest (high first), then alphabetically within each tier
    classified.sort(key=lambda x: (interest_order.get(x["interest"], 9), x["subdomain"]))

    groups = _detect_groups(classified, base_domain)

    stats = Counter(item["interest"] for item in classified)

    return {
        "classified": classified,
        "categories": dict(cat_counts),
        "groups": groups,
        "stats": {
            "high_interest": stats.get("high", 0),
            "medium_interest": stats.get("medium", 0),
            "low_interest": stats.get("low", 0),
        },
    }


# ---------------------------------------------------------------------------
# subfinder command + parser
# ---------------------------------------------------------------------------

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

    # Derive base domain from the subdomains for classification
    if result["subdomains"]:
        sample = result["subdomains"][0]
        parts = sample.split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else sample
    else:
        base_domain = ""

    if base_domain and result["subdomains"]:
        classification = classify_subdomains(
            result["subdomains"], result["sources"], base_domain
        )
        result.update(classification)

    return result
