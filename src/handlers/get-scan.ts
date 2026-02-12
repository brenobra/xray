import type { Env, ScanRow } from "../types";
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
  return jsonResponse(response, origin);
}
