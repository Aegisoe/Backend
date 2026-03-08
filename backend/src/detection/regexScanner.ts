import { calculateEntropy } from "./entropyAnalyzer";

// ── Secret Patterns ──────────────────────────────────────────────

const SECRET_PATTERNS: Record<string, RegExp> = {
  // ── Well-known API keys ──
  openai:       /sk-[a-zA-Z0-9_\-]{20,}/g,
  aws:          /AKIA[0-9A-Z]{16}/g,
  github:       /gh[ps]_[a-zA-Z0-9]{36,}/g,
  gitlab:       /glpat-[a-zA-Z0-9_\-]{20,}/g,
  slack_webhook: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g,
  slack_token:  /xox[bpras]-[a-zA-Z0-9\-]+/g,
  stripe:       /sk_live_[a-zA-Z0-9]{24,}/g,
  stripe_test:  /sk_test_[a-zA-Z0-9]{24,}/g,
  google_api:   /AIza[a-zA-Z0-9_\-]{35}/g,
  firebase:     /AAAA[a-zA-Z0-9_\-]{7}:[a-zA-Z0-9_\-]{140,}/g,
  twilio:       /SK[a-f0-9]{32}/g,
  sendgrid:     /SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g,
  mailgun:      /key-[a-zA-Z0-9]{32}/g,
  jwt:          /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
  // ── Private keys ──
  private_key:  /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
  // ── Database / connection strings ──
  database_url: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s'"]+/g,
  // ── .env style: KEY=value (sensitive variable names) ──
  env_secret:   /(?:^|[\s;])(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|API_SECRET|ACCESS_KEY|PRIVATE_KEY|DB_PASSWORD|DATABASE_URL|MONGO_URI|REDIS_URL|AUTH_TOKEN|JWT_SECRET|ENCRYPTION_KEY|MASTER_KEY|CLIENT_SECRET|APP_SECRET|SESSION_SECRET)[=:]\s*['"]?([^\s'"#]+)['"]?/gi,
  // ── Generic high-entropy (last resort) ──
  generic:      /[a-zA-Z0-9_\-]{32,64}/g,
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

      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(line)) !== null) {
        // For env_secret pattern, use captured group (the value), not full match
        const value = type === "env_secret" && match[1] ? match[1] : match[0];
        if (seen.has(value)) continue;
        if (value.length < 8) continue; // skip very short values

        // private_key and database_url don't need entropy check
        const skipEntropyCheck = ["private_key", "database_url", "slack_webhook", "env_secret"].includes(type);
        const entropy = calculateEntropy(value);

        if (skipEntropyCheck || entropy > ENTROPY_THRESHOLD) {
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
