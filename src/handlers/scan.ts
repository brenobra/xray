import { getContainer } from "@cloudflare/containers";
import type { Env } from "../types";
import { jsonResponse } from "../lib/response";
import {
  extractHostname,
  isBlockedHostname,
  simpleHash,
} from "../lib/validation";
import { computeSecurityScore } from "../lib/scoring";

export async function handleScan(
  request: Request,
  env: Env
): Promise<Response> {
  const origin = env.ALLOWED_ORIGIN;
  const body = (await request.json()) as { target?: string };
  const target = body?.target?.trim();

  if (!target) {
    return jsonResponse({ error: "Missing 'target' field" }, origin, 400);
  }

  // Validate hostname before sending to container
  const hostname = extractHostname(target);
  if (!hostname) {
    return jsonResponse(
      {
        error:
          "Invalid target. Please enter a valid domain (e.g., example.com)",
      },
      origin,
      400
    );
  }

  // Block internal/private targets to prevent SSRF
  if (isBlockedHostname(hostname)) {
    return jsonResponse(
      { error: "Scanning internal or reserved hostnames is not allowed" },
      origin,
      400
    );
  }

  const scanId = crypto.randomUUID();

  // Record scan as running
  await env.DB.prepare(
    "INSERT INTO scans (id, target, status) VALUES (?, ?, 'running')"
  )
    .bind(scanId, target)
    .run();

  // Route to container instance (hash-based for parallel utilization)
  const POOL_COUNT = 5;
  const poolIndex = simpleHash(target) % POOL_COUNT;
  const container = getContainer(env.SCANNER, `scanner-pool-${poolIndex}`);

  try {
    const containerResponse = await container.fetch(
      new Request("http://container/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      })
    );

    if (!containerResponse.ok) {
      const errText = await containerResponse.text();
      await env.DB.prepare(
        "UPDATE scans SET status = 'failed', error = ?, completed_at = datetime('now') WHERE id = ?"
      )
        .bind(errText, scanId)
        .run();
      return jsonResponse({ error: errText, scan_id: scanId }, origin, 502);
    }

    const results = (await containerResponse.json()) as Record<
      string,
      unknown
    >;

    // Compute security score
    results.security_score = computeSecurityScore(
      results as Parameters<typeof computeSecurityScore>[0]
    );

    const resultsJson = JSON.stringify(results);
    const durationMs =
      typeof results.duration_ms === "number" ? results.duration_ms : 0;

    // Persist to D1
    await env.DB.prepare(
      "UPDATE scans SET status = 'completed', results = ?, completed_at = datetime('now'), duration_ms = ? WHERE id = ?"
    )
      .bind(resultsJson, durationMs, scanId)
      .run();

    // Archive to R2 (non-critical)
    try {
      await env.ARCHIVE.put(`scans/${scanId}.json`, resultsJson, {
        httpMetadata: { contentType: "application/json" },
      });
    } catch (r2Err) {
      console.error("R2 archival failed:", r2Err);
    }

    return jsonResponse({ scan_id: scanId, ...results }, origin);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    await env.DB.prepare(
      "UPDATE scans SET status = 'failed', error = ?, completed_at = datetime('now') WHERE id = ?"
    )
      .bind(message, scanId)
      .run();
    return jsonResponse(
      { error: "Scanner unavailable: " + message, scan_id: scanId },
      origin,
      503
    );
  }
}
