export interface ScoreBreakdown {
  tls: number;
  headers: number;
  waf: number;
  certificate: number;
  server_exposure: number;
}

export interface ScoreResult {
  score: number;
  grade: string;
  breakdown: ScoreBreakdown;
  recommendations: string[];
}

interface ScanData {
  tls?: {
    protocols?: string[];
    cipher_suites?: string[];
    certificate?: { issuer?: string; expiry?: string; san?: string[] };
  };
  headers?: {
    server?: string;
    security_headers?: Record<string, string>;
  };
  waf?: { detected?: boolean };
}

const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "x-xss-protection",
  "referrer-policy",
  "permissions-policy",
];

function scoreTls(data: ScanData): { score: number; recs: string[] } {
  const protocols = data.tls?.protocols ?? [];
  const recs: string[] = [];
  if (protocols.length === 0) return { score: 0, recs: ["No TLS detected"] };

  let score = 25;
  const hasLegacy =
    protocols.some((p) => p.includes("1.0")) ||
    protocols.some((p) => p.includes("1.1"));
  const has13 = protocols.some((p) => p.includes("1.3"));

  if (hasLegacy) {
    score -= 10;
    recs.push("Disable TLS 1.0/1.1 — they have known vulnerabilities");
  }
  if (!has13) {
    score -= 5;
    recs.push("Enable TLS 1.3 for better performance and security");
  }

  return { score: Math.max(score, 0), recs };
}

function scoreHeaders(data: ScanData): { score: number; recs: string[] } {
  const sec = data.headers?.security_headers ?? {};
  const recs: string[] = [];
  let present = 0;

  for (const header of SECURITY_HEADERS) {
    const val = sec[header];
    if (val && val !== "missing" && val !== "") {
      present++;
    } else {
      recs.push(`Add ${header} header`);
    }
  }

  const score = Math.round((present / SECURITY_HEADERS.length) * 30);
  return { score, recs };
}

function scoreWaf(data: ScanData): { score: number; recs: string[] } {
  if (data.waf?.detected) return { score: 15, recs: [] };
  return {
    score: 0,
    recs: ["Consider deploying a Web Application Firewall"],
  };
}

function scoreCertificate(data: ScanData): { score: number; recs: string[] } {
  const cert = data.tls?.certificate;
  const recs: string[] = [];
  if (!cert || !cert.expiry) return { score: 0, recs: ["No certificate found"] };

  let score = 20;

  // Check expiry
  const expiry = new Date(cert.expiry);
  const now = new Date();
  const daysUntilExpiry = (expiry.getTime() - now.getTime()) / 86_400_000;
  if (daysUntilExpiry < 0) {
    score -= 20;
    recs.push("Certificate has expired!");
  } else if (daysUntilExpiry < 30) {
    score -= 10;
    recs.push(`Certificate expires in ${Math.round(daysUntilExpiry)} days — renew soon`);
  }

  return { score: Math.max(score, 0), recs };
}

function scoreServerExposure(data: ScanData): {
  score: number;
  recs: string[];
} {
  const server = data.headers?.server ?? "";
  const recs: string[] = [];
  let score = 10;

  if (server && server !== "N/A") {
    // Check if version info is leaked (e.g., "Apache/2.4.41")
    if (/\/[\d.]/.test(server)) {
      score -= 5;
      recs.push(
        `Server header exposes version info (${server}) — consider hiding it`
      );
    }
  }

  return { score: Math.max(score, 0), recs };
}

function gradeFromScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

export function computeSecurityScore(data: ScanData): ScoreResult {
  const tls = scoreTls(data);
  const headers = scoreHeaders(data);
  const waf = scoreWaf(data);
  const certificate = scoreCertificate(data);
  const serverExposure = scoreServerExposure(data);

  const score =
    tls.score +
    headers.score +
    waf.score +
    certificate.score +
    serverExposure.score;

  return {
    score,
    grade: gradeFromScore(score),
    breakdown: {
      tls: tls.score,
      headers: headers.score,
      waf: waf.score,
      certificate: certificate.score,
      server_exposure: serverExposure.score,
    },
    recommendations: [
      ...tls.recs,
      ...headers.recs,
      ...waf.recs,
      ...certificate.recs,
      ...serverExposure.recs,
    ],
  };
}
