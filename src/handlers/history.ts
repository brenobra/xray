import type { Env, ScanRow } from "../types";
import { jsonResponse } from "../lib/response";

export async function handleHistory(
  request: Request,
  env: Env
): Promise<Response> {
  const url = new URL(request.url);
  const search = url.searchParams.get("q") || "";
  const status = url.searchParams.get("status") || "";
  const limit = Math.min(
    Math.max(parseInt(url.searchParams.get("limit") || "50", 10) || 50, 1),
    200
  );
  const cursor = url.searchParams.get("cursor") || "";

  let query =
    "SELECT id, target, status, created_at, completed_at, duration_ms FROM scans WHERE 1=1";
  const binds: unknown[] = [];

  if (search) {
    query += " AND target LIKE ?";
    binds.push(`%${search}%`);
  }
  if (status) {
    query += " AND status = ?";
    binds.push(status);
  }
  if (cursor) {
    query += " AND created_at < ?";
    binds.push(cursor);
  }

  // Fetch limit+1 to detect if there are more results
  query += " ORDER BY created_at DESC LIMIT ?";
  binds.push(limit + 1);

  const result = await env.DB.prepare(query)
    .bind(...binds)
    .all<ScanRow>();

  const scans = result.results ?? [];
  const hasMore = scans.length > limit;
  const page = hasMore ? scans.slice(0, limit) : scans;
  const nextCursor = hasMore ? page[page.length - 1].created_at : null;

  return jsonResponse({ scans: page, next_cursor: nextCursor }, env.ALLOWED_ORIGIN);
}
