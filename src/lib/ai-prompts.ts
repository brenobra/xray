// ---------------------------------------------------------------------------
// Workers AI Prompt Engineering for Cloudflare Opportunity Reports
// ---------------------------------------------------------------------------

export const AI_MODEL = "@cf/meta/llama-3.1-8b-instruct-fp8" as const;

type ChatMessage = { role: "system" | "user"; content: string };
export type PromptPayload = {
  messages: ChatMessage[];
  response_format: { type: "json_object" };
};

// ---------------------------------------------------------------------------
// Shared CF Product Context (injected into every prompt)
// ---------------------------------------------------------------------------

const CF_PRODUCTS = `Cloudflare Product Portfolio (use exact names):
- CDN & Caching: Cloudflare CDN, Cache Rules, Tiered Cache, Argo Smart Routing
- Security: Cloudflare WAF, DDoS Protection, Bot Management, API Shield, Page Shield, Turnstile
- SSL/TLS: Cloudflare SSL, Advanced Certificate Manager, Keyless SSL, automatic TLS 1.3
- Zero Trust: Cloudflare Access, Gateway, Tunnel, WARP, Browser Isolation, CASB
- Email: Area 1 Email Security, Email Routing
- DNS: Cloudflare Authoritative DNS, DNS Firewall, DNSSEC
- Compute & Developer: Workers, Pages, R2, D1, Durable Objects, KV, Queues, Workers AI
- Network: Spectrum, Magic Transit, Magic WAN, China Network
- Performance: Early Hints, Zaraz, Web Analytics, Speed Brain
- Media: Cloudflare Images, Stream, Image Resizing`;

// ---------------------------------------------------------------------------
// Input Compression — build a condensed scan summary for AI
// ---------------------------------------------------------------------------

interface ScanSummary {
  target: string;
  waf: { detected: boolean; provider?: string };
  technologies: Array<{ name: string; version?: string; category?: string }>;
  tls: {
    protocols: string[];
    cipher_suites: string[];
    certificate?: { issuer?: string; expiry?: string };
  };
  dns: {
    a_records: string[];
    cname_records: string[];
    ns_records: string[];
    mx_records: string[];
    cdn_detected?: string;
    hosting_provider?: string;
  };
  headers: {
    server?: string;
    security_headers: Record<string, string>;
    redirect_chain?: Array<{ url: string; status_code: number; location?: string }>;
    final_url?: string;
  };
  ip_info: { ip?: string; asn?: string; org?: string };
  whois: {
    registrar?: string;
    nameservers?: string[];
    creation_date?: string;
    expiry_date?: string;
  };
  subdomains: {
    total: number;
    stats?: { high_interest?: number; medium_interest?: number; low_interest?: number };
    categories?: Record<string, number>;
    sample_by_category?: Record<string, string[]>;
    groups?: Array<{ prefix: string; count: number; category: string }>;
  };
  security_score?: {
    score: number;
    grade: string;
    breakdown: Record<string, number>;
    recommendations: string[];
  };
}

/* eslint-disable @typescript-eslint/no-explicit-any */
export function buildScanSummary(raw: Record<string, any>): ScanSummary {
  const subs = raw.subdomains ?? {};
  const classified: any[] = subs.classified ?? [];

  // Build category counts and samples (max 3 per category)
  const categories: Record<string, number> = {};
  const samples: Record<string, string[]> = {};
  for (const item of classified) {
    const cat = item.category ?? "Unknown";
    categories[cat] = (categories[cat] ?? 0) + 1;
    if (!samples[cat]) samples[cat] = [];
    if (samples[cat].length < 3) samples[cat].push(item.subdomain);
  }

  return {
    target: raw.target ?? "",
    waf: {
      detected: raw.waf?.detected ?? false,
      provider: raw.waf?.provider,
    },
    technologies: (raw.technologies ?? []).map((t: any) => ({
      name: t.name,
      version: t.version || undefined,
      category: t.category !== "Unknown" ? t.category : undefined,
    })),
    tls: {
      protocols: raw.tls?.protocols ?? [],
      cipher_suites: (raw.tls?.cipher_suites ?? []).slice(0, 5),
      certificate: raw.tls?.certificate
        ? { issuer: raw.tls.certificate.issuer, expiry: raw.tls.certificate.expiry }
        : undefined,
    },
    dns: {
      a_records: raw.dns?.a_records ?? [],
      cname_records: raw.dns?.cname_records ?? [],
      ns_records: raw.dns?.ns_records ?? [],
      mx_records: raw.dns?.mx_records ?? [],
      cdn_detected: raw.dns?.cdn_detected,
      hosting_provider: raw.dns?.hosting_provider,
    },
    headers: {
      server: raw.headers?.server,
      security_headers: raw.headers?.security_headers ?? {},
      redirect_chain: raw.headers?.redirect_chain,
      final_url: raw.headers?.final_url,
    },
    ip_info: raw.ip_info ?? {},
    whois: {
      registrar: raw.whois?.registrar,
      nameservers: raw.whois?.nameservers,
      creation_date: raw.whois?.creation_date,
      expiry_date: raw.whois?.expiry_date,
    },
    subdomains: {
      total: (subs.subdomains ?? []).length,
      stats: subs.stats,
      categories,
      sample_by_category: samples,
      groups: (subs.groups ?? []).map((g: any) => ({
        prefix: g.prefix,
        count: g.count,
        category: g.category,
      })),
    },
    security_score: raw.security_score,
  };
}
/* eslint-enable @typescript-eslint/no-explicit-any */

// ---------------------------------------------------------------------------
// Prompt Builders
// ---------------------------------------------------------------------------

function system(sectionInstructions: string): string {
  return `You are a Cloudflare solutions engineer analyzing a website's infrastructure for competitive displacement opportunities. Your audience is other Cloudflare sales/solutions engineers who need actionable intelligence.

${CF_PRODUCTS}

${sectionInstructions}

Respond ONLY with valid JSON matching the schema described. No markdown, no explanation outside the JSON.`;
}

export function buildOpportunitySummaryPrompt(summary: ScanSummary): PromptPayload {
  return {
    messages: [
      {
        role: "system",
        content: system(`Analyze the scan data and produce a Cloudflare opportunity summary.

Return JSON: {"narrative":"string (2-3 paragraphs)","top_opportunities":[{"area":"string","product":"string","impact":"high|medium|low"}]}

The narrative should:
- Open with what the site currently uses (vendors, CDN, WAF, DNS, hosting)
- Highlight the strongest Cloudflare displacement opportunities
- Note security weaknesses that Cloudflare fixes easily

top_opportunities: max 5 items, sorted by impact (high first).`),
      },
      { role: "user", content: JSON.stringify(summary) },
    ],
    response_format: { type: "json_object" },
  };
}

export function buildVendorMappingPrompt(summary: ScanSummary): PromptPayload {
  return {
    messages: [
      {
        role: "system",
        content: system(`Identify all detected third-party vendors and technologies, and map each to the best Cloudflare replacement.

Return JSON: {"vendors":[{"detected_vendor":"string","vendor_category":"string","cf_replacement":"string","talking_points":["string"],"confidence":"high|medium|low"}]}

Sources of vendor info: WAF provider, CDN vendor from DNS, technology stack names, hosting provider, nameservers, email (MX records), subdomain patterns suggesting competitor products.

Only include vendors where Cloudflare has a competitive replacement. 2-3 talking points per vendor focusing on concrete advantages.`),
      },
      { role: "user", content: JSON.stringify(summary) },
    ],
    response_format: { type: "json_object" },
  };
}

export function buildSecurityGapsPrompt(summary: ScanSummary): PromptPayload {
  return {
    messages: [
      {
        role: "system",
        content: system(`Map each security weakness to a specific Cloudflare product with a business justification.

Return JSON: {"gaps":[{"gap":"string","severity":"high|medium|low","cf_product":"string","cf_feature":"string","business_pitch":"string"}]}

Look at: security_score (grade, breakdown, recommendations), missing security headers, TLS configuration, WAF status, certificate expiry, server version exposure, redirect chain issues.

business_pitch should be 1-2 sentences a sales engineer can use in conversation. Be specific about the CF feature, not generic.`),
      },
      { role: "user", content: JSON.stringify(summary) },
    ],
    response_format: { type: "json_object" },
  };
}

export function buildInfraIntelPrompt(summary: ScanSummary): PromptPayload {
  return {
    messages: [
      {
        role: "system",
        content: system(`Analyze the subdomain and infrastructure data to infer patterns, shadow IT, and multi-cloud usage.

Return JSON: {"patterns":["string"],"shadow_it_indicators":["string"],"multi_cloud_detected":boolean,"cloud_providers":["string"],"infrastructure_summary":"string (1-2 paragraphs)"}

Look at: subdomain categories, subdomain naming patterns (groups), hosting provider, CDN vendor, DNS nameservers, technology stack, CNAME records.

patterns: infrastructure patterns you can infer (e.g., "Kubernetes cluster detected from node-* subdomains", "SaaS-heavy stack with multiple vendors").
shadow_it_indicators: services that may be unmanaged or forgotten.
cloud_providers: list cloud providers detected from any signal.`),
      },
      { role: "user", content: JSON.stringify(summary) },
    ],
    response_format: { type: "json_object" },
  };
}

export function buildMigrationPrompt(summary: ScanSummary): PromptPayload {
  return {
    messages: [
      {
        role: "system",
        content: system(`Assess migration complexity for each detected technology component to its Cloudflare equivalent.

Return JSON: {"components":[{"component":"string","current_vendor":"string","complexity":"easy|medium|hard","estimated_effort":"string","approach":"string (1-2 sentences)","cf_products":["string"],"risks":["string"]}]}

Complexity guide:
- easy: DNS/config change only (DNS migration, CDN proxy, WAF enable, SSL)
- medium: requires some config or policy migration (email routing, header rules, access policies)
- hard: requires code changes or deep integration work (compute migration, custom WAF rules, full Zero Trust rollout)

Order by complexity (easy first). Include a migration sequence recommendation in the first component's approach.`),
      },
      { role: "user", content: JSON.stringify(summary) },
    ],
    response_format: { type: "json_object" },
  };
}

// ---------------------------------------------------------------------------
// Response Parsing
// ---------------------------------------------------------------------------

export function parseAiResponse<T>(raw: string | undefined | null, fallback: T): T {
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return parsed as T;
  } catch {
    return fallback;
  }
}
