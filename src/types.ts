import type { ScannerContainer } from "./index";

export interface Env {
  SCANNER: DurableObjectNamespace<ScannerContainer>;
  DB: D1Database;
  ARCHIVE: R2Bucket;
  ASSETS: Fetcher;
  ALLOWED_ORIGIN: string;
  AI: Ai;
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

// ---------------------------------------------------------------------------
// AI Report Types
// ---------------------------------------------------------------------------

export interface AiReportRow {
  scan_id: string;
  report: string;
  model: string;
  generated_at: string;
  generation_ms: number | null;
}

export interface OpportunitySummary {
  narrative: string;
  top_opportunities: Array<{
    area: string;
    product: string;
    impact: "high" | "medium" | "low";
  }>;
}

export interface VendorMapping {
  detected_vendor: string;
  vendor_category: string;
  cf_replacement: string;
  talking_points: string[];
  confidence: "high" | "medium" | "low";
}

export interface SecurityGap {
  gap: string;
  severity: "high" | "medium" | "low";
  cf_product: string;
  cf_feature: string;
  business_pitch: string;
}

export interface InfrastructureIntelligence {
  patterns: string[];
  shadow_it_indicators: string[];
  multi_cloud_detected: boolean;
  cloud_providers: string[];
  infrastructure_summary: string;
}

export interface MigrationComponent {
  component: string;
  current_vendor: string;
  complexity: "easy" | "medium" | "hard";
  estimated_effort: string;
  approach: string;
  cf_products: string[];
  risks: string[];
}

export interface AiReport {
  opportunity_summary: OpportunitySummary | null;
  vendor_mapping: VendorMapping[];
  security_gaps: SecurityGap[];
  infrastructure_intelligence: InfrastructureIntelligence | null;
  migration_assessment: MigrationComponent[];
}

export interface AiReportResponse {
  scan_id: string;
  target: string;
  generated_at: string;
  cached: boolean;
  generation_ms: number | null;
  report: AiReport;
  errors: string[];
}
