import type {
  Env,
  ScanRow,
  AiReportRow,
  AiReport,
  AiReportResponse,
  OpportunitySummary,
  VendorMapping,
  SecurityGap,
  InfrastructureIntelligence,
  MigrationComponent,
} from "../types";
import { jsonResponse } from "../lib/response";
import {
  AI_MODEL,
  buildScanSummary,
  buildOpportunitySummaryPrompt,
  buildVendorMappingPrompt,
  buildSecurityGapsPrompt,
  buildInfraIntelPrompt,
  buildMigrationPrompt,
  parseAiResponse,
  type PromptPayload,
} from "../lib/ai-prompts";

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function handleAnalyze(
  id: string,
  env: Env
): Promise<Response> {
  const origin = env.ALLOWED_ORIGIN;

  if (!UUID_RE.test(id)) {
    return jsonResponse({ error: "Invalid scan ID" }, origin, 400);
  }

  // Check cache
  const cached = await env.DB.prepare(
    "SELECT report, generated_at, generation_ms FROM ai_reports WHERE scan_id = ?"
  )
    .bind(id)
    .first<AiReportRow>();

  if (cached) {
    const report = parseAiResponse<AiReport>(cached.report, null as unknown as AiReport);
    if (report) {
      const scanRow = await env.DB.prepare(
        "SELECT target FROM scans WHERE id = ?"
      )
        .bind(id)
        .first<{ target: string }>();

      return jsonResponse(
        {
          scan_id: id,
          target: scanRow?.target ?? "",
          generated_at: cached.generated_at,
          cached: true,
          generation_ms: cached.generation_ms,
          report,
          errors: [],
        } satisfies AiReportResponse,
        origin
      );
    }
  }

  // Load scan results
  const row = await env.DB.prepare("SELECT * FROM scans WHERE id = ?")
    .bind(id)
    .first<ScanRow>();

  if (!row) return jsonResponse({ error: "Scan not found" }, origin, 404);
  if (row.status !== "completed" || !row.results) {
    return jsonResponse({ error: "Scan is not completed" }, origin, 400);
  }

  let scanResults: Record<string, unknown>;
  try {
    scanResults = JSON.parse(row.results);
  } catch {
    return jsonResponse({ error: "Corrupted scan data" }, origin, 500);
  }

  // Build condensed summary
  const summary = buildScanSummary(scanResults);
  const startTime = Date.now();

  // Run all 5 AI calls in parallel
  const [s1, s2, s3, s4, s5] = await Promise.allSettled([
    runSection(env, buildOpportunitySummaryPrompt(summary)),
    runSection(env, buildVendorMappingPrompt(summary)),
    runSection(env, buildSecurityGapsPrompt(summary)),
    runSection(env, buildInfraIntelPrompt(summary)),
    runSection(env, buildMigrationPrompt(summary)),
  ]);

  // Assemble report with graceful fallbacks
  const errors: string[] = [];

  const opportunityRaw = extractResult(s1, errors, "opportunity_summary");
  const vendorRaw = extractResult(s2, errors, "vendor_mapping");
  const securityRaw = extractResult(s3, errors, "security_gaps");
  const infraRaw = extractResult(s4, errors, "infrastructure_intelligence");
  const migrationRaw = extractResult(s5, errors, "migration_assessment");

  const report: AiReport = {
    opportunity_summary: opportunityRaw as OpportunitySummary | null,
    vendor_mapping: (vendorRaw as { vendors?: VendorMapping[] })?.vendors ?? [],
    security_gaps: (securityRaw as { gaps?: SecurityGap[] })?.gaps ?? [],
    infrastructure_intelligence: infraRaw as InfrastructureIntelligence | null,
    migration_assessment:
      (migrationRaw as { components?: MigrationComponent[] })?.components ?? [],
  };

  const generationMs = Date.now() - startTime;

  // Cache in D1 (non-critical)
  try {
    await env.DB.prepare(
      "INSERT OR REPLACE INTO ai_reports (scan_id, report, model, generated_at, generation_ms) VALUES (?, ?, ?, datetime('now'), ?)"
    )
      .bind(id, JSON.stringify(report), AI_MODEL, generationMs)
      .run();
  } catch (e) {
    console.error("Failed to cache AI report:", e);
  }

  return jsonResponse(
    {
      scan_id: id,
      target: row.target,
      generated_at: new Date().toISOString(),
      cached: false,
      generation_ms: generationMs,
      report,
      errors,
    } satisfies AiReportResponse,
    origin
  );
}

async function runSection(
  env: Env,
  prompt: PromptPayload
): Promise<unknown> {
  const result = await env.AI.run(AI_MODEL, {
    messages: prompt.messages,
    response_format: prompt.response_format,
    max_tokens: 2048,
    temperature: 0.3,
  });

  const raw =
    typeof result === "string"
      ? result
      : (result as { response?: string }).response ?? "";

  return JSON.parse(raw);
}

function extractResult(
  settled: PromiseSettledResult<unknown>,
  errors: string[],
  sectionName: string
): unknown | null {
  if (settled.status === "fulfilled") {
    return settled.value;
  }
  const reason =
    settled.reason instanceof Error
      ? settled.reason.message
      : String(settled.reason);
  errors.push(`${sectionName}: ${reason}`);
  return null;
}
