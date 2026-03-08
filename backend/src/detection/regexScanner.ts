import { calculateEntropy } from "./entropyAnalyzer";

// ── Secret Patterns ──────────────────────────────────────────────

const SECRET_PATTERNS: Record<string, RegExp> = {
  // sk-[a-zA-Z0-9_-] covers both old (sk-xxx) and new (sk-proj-xxx) OpenAI formats
  openai:   /sk-[a-zA-Z0-9_\-]{20,}/g,
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

// ── Multi-match Scanner (untuk Repo Scanner) ────────────────────
// Scan seluruh text dan return SEMUA secret yang ditemukan

export interface SecretMatch {
  secretType: string;
  matchedValue: string;
  maskedValue: string;
  entropy: number;
  line: number;
}

function maskSecretValue(value: string): string {
  if (value.length <= 10) return "***";
  return `${value.substring(0, 7)}...${"*".repeat(6)} (${value.length} chars)`;
}

export function scanTextForAllSecrets(text: string): SecretMatch[] {
  const matches: SecretMatch[] = [];
  const lines = text.split("\n");
  const seen = new Set<string>(); // deduplicate exact matches

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip comment-only lines and very short lines
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("#")) continue;

    // Check known patterns first
    for (const [type, pattern] of Object.entries(SECRET_PATTERNS)) {
      if (type === "generic") continue;

      const regex = new RegExp(pattern.source, "g");
      let match;
      while ((match = regex.exec(line)) !== null) {
        const value = match[0];
        if (seen.has(value)) continue;

        const entropy = calculateEntropy(value);
        if (entropy > ENTROPY_THRESHOLD) {
          seen.add(value);
          matches.push({
            secretType: type,
            matchedValue: value,
            maskedValue: maskSecretValue(value),
            entropy,
            line: i + 1,
          });
        }
      }
    }

    // Generic high-entropy fallback
    const genericRegex = new RegExp(SECRET_PATTERNS.generic.source, "g");
    let gMatch;
    while ((gMatch = genericRegex.exec(line)) !== null) {
      const value = gMatch[0];
      if (seen.has(value)) continue;

      const entropy = calculateEntropy(value);
      if (entropy > ENTROPY_THRESHOLD + 0.5) {
        seen.add(value);
        matches.push({
          secretType: "generic",
          matchedValue: value,
          maskedValue: maskSecretValue(value),
          entropy,
          line: i + 1,
        });
      }
    }
  }

  return matches;
}
