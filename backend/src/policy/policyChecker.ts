/**
 * Rotation Policy Checker
 *
 * Menentukan apakah secret yang terdeteksi harus di-rotate otomatis
 * atau menunggu manual approval.
 */

// ── Types ────────────────────────────────────────────────────────

export interface PolicyResult {
  autoRotate: boolean;
  reason: string;
}

// ── Risk Level per Secret Type ───────────────────────────────────

const SECRET_RISK: Record<string, "critical" | "high" | "medium"> = {
  openai:   "critical",
  aws:      "critical",
  github:   "high",
  jwt:      "high",
  generic:  "medium",
};

// ── Policy Rules ─────────────────────────────────────────────────

export function shouldAutoRotate(secretType: string): PolicyResult {
  const risk = SECRET_RISK[secretType] || "medium";

  switch (risk) {
    case "critical":
      return {
        autoRotate: true,
        reason: `${secretType} key is CRITICAL risk — auto-rotating immediately`,
      };
    case "high":
      return {
        autoRotate: true,
        reason: `${secretType} key is HIGH risk — auto-rotating`,
      };
    case "medium":
    default:
      return {
        autoRotate: false,
        reason: `${secretType} key is MEDIUM risk — manual approval required`,
      };
  }
}
