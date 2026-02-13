import type { Env, ScanRow, AiReportRow } from "../types";
import { jsonResponse } from "../lib/response";

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function handleGetScan(
  id: string,
  env: Env
): Promise<Response> {
  const origin = env.ALLOWED_ORIGIN;

  if (!UUID_RE.test(id)) {
    return jsonResponse({ error: "Invalid scan ID" }, origin, 400);
  }

  const row = await env.DB.prepare("SELECT * FROM scans WHERE id = ?")
    .bind(id)
    .first<ScanRow>();

  if (!row) {
    return jsonResponse({ error: "Scan not found" }, origin, 404);
  }

  const response: Record<string, unknown> = { ...row };
  if (row.results) {
    try {
      response.results = JSON.parse(row.results);
    } catch {
      // leave as string
    }
  }

  // Include cached AI report if available
  const aiRow = await env.DB.prepare(
    "SELECT report, generated_at, generation_ms FROM ai_reports WHERE scan_id = ?"
  )
    .bind(id)
    .first<AiReportRow>();

  if (aiRow) {
    try {
      response.ai_report = {
        report: JSON.parse(aiRow.report),
        generated_at: aiRow.generated_at,
        generation_ms: aiRow.generation_ms,
        cached: true,
      };
    } catch {
      // ignore parse errors
    }
  }

  return jsonResponse(response, origin);
}
