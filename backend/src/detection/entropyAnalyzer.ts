/**
 * Shannon Entropy Calculator
 *
 * Mengukur keacakan sebuah string.
 * Semakin tinggi entropy → semakin acak → semakin mungkin ini adalah secret.
 *
 * Threshold yang digunakan AEGISOE: > 4.5 bits per character
 *
 * Referensi:
 * - Random API keys biasanya: 4.5–5.5 bits/char
 * - Normal words/code: < 4.0 bits/char
 * - "password123": ~3.2 bits/char
 * - "sk-aBc123XyZ789...": ~4.8 bits/char
 */

export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  // Hitung frekuensi setiap karakter
  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }

  // Hitung Shannon entropy
  const entropy = -Object.values(freq)
    .map((count) => count / str.length)
    .reduce((sum, p) => sum + p * Math.log2(p), 0);

  return entropy;
}

// ── Utility ──────────────────────────────────────────────────────

export function isHighEntropy(str: string, threshold = 4.5): boolean {
  return calculateEntropy(str) > threshold;
}
