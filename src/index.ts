import { Container } from "@cloudflare/containers";
import type { Env } from "./types";
import { corsHeaders, jsonResponse } from "./lib/response";
import { handleScan } from "./handlers/scan";
import { handleHistory } from "./handlers/history";
import { handleGetScan } from "./handlers/get-scan";

// =============================================================================
// Container Durable Object
// =============================================================================

export class ScannerContainer extends Container<Env> {
  defaultPort = 8080;
  sleepAfter = "5m";
  enableInternet = true;

  override onStart(): void {
    console.log("[ScannerContainer] started");
  }

  override onStop(): void {
    console.log("[ScannerContainer] stopped");
  }

  override onError(error: unknown): void {
    console.error("[ScannerContainer] error:", error);
  }
}

// =============================================================================
// Worker Entry Point
// =============================================================================

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: corsHeaders(env.ALLOWED_ORIGIN),
      });
    }

    try {
      if (path === "/api/scan" && request.method === "POST") {
        return await handleScan(request, env);
      }
      if (path === "/api/history" && request.method === "GET") {
        return await handleHistory(request, env);
      }
      if (path.startsWith("/api/scan/") && request.method === "GET") {
        const id = path.slice("/api/scan/".length);
        return await handleGetScan(id, env);
      }

      // Serve static frontend assets
      return env.ASSETS.fetch(request);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Internal error";
      console.error("Worker error:", err);
      return jsonResponse({ error: message }, env.ALLOWED_ORIGIN, 500);
    }
  },
} satisfies ExportedHandler<Env>;
