import type { ScannerContainer } from "./index";

export interface Env {
  SCANNER: DurableObjectNamespace<ScannerContainer>;
  DB: D1Database;
  ARCHIVE: R2Bucket;
  ASSETS: Fetcher;
  ALLOWED_ORIGIN: string;
}

export interface ScanRow {
  id: string;
  target: string;
  status: string;
  results: string | null;
  error: string | null;
  created_at: string;
  completed_at: string | null;
  duration_ms: number | null;
}
