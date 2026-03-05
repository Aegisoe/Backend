import { calculateEntropy } from "./entropyAnalyzer";

// ── Secret Patterns ──────────────────────────────────────────────

const SECRET_PATTERNS: Record<string, RegExp> = {
  openai:   /sk-[a-zA-Z0-9]{20,}/g,
  aws:      /AKIA[0-9A-Z]{16}/g,
  github:   /ghp_[a-zA-Z0-9]{36}/g,
  jwt:      /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
  generic:  /[a-zA-Z0-9_\-]{32,64}/g,
};

// Entropy threshold — string dengan entropy tinggi kemungkinan besar secret
const ENTROPY_THRESHOLD = 4.5;

// ── Types ────────────────────────────────────────────────────────

export interface ScanResult {
  hasSecret: boolean;
  secretType: string | null;
  matchedValue: string | null;
  entropy: number | null;
}

// ── Main Scanner ─────────────────────────────────────────────────

export function scanDiffForSecrets(diff: string): ScanResult {
  // Cek pattern yang sudah dikenal dulu (lebih akurat)
  for (const [type, pattern] of Object.entries(SECRET_PATTERNS)) {
    if (type === "generic") continue; // generic dicek terakhir

    pattern.lastIndex = 0; // reset regex state
    const match = pattern.exec(diff);

    if (match) {
      const value = match[0];
      const entropy = calculateEntropy(value);

      if (entropy > ENTROPY_THRESHOLD) {
        return {
          hasSecret: true,
          secretType: type,
          matchedValue: value,
          entropy,
        };
      }
    }
  }

  // Fallback: generic high-entropy string detection
  const genericPattern = SECRET_PATTERNS.generic;
  genericPattern.lastIndex = 0;

  let match;
  while ((match = genericPattern.exec(diff)) !== null) {
    const value = match[0];
    const entropy = calculateEntropy(value);

    if (entropy > ENTROPY_THRESHOLD + 0.5) {
      return {
        hasSecret: true,
        secretType: "generic",
        matchedValue: value,
        entropy,
      };
    }
  }

  return {
    hasSecret: false,
    secretType: null,
    matchedValue: null,
    entropy: null,
  };
}
