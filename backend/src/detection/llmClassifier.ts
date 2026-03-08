/**
 * LLM Secret Classifier
 *
 * Step 3 dari detection pipeline:
 *   1. Regex (regexScanner.ts)
 *   2. Entropy (entropyAnalyzer.ts)
 *   3. LLM (llmClassifier.ts) ← ini
 *
 * Mengirim kandidat secret ke Groq API (LLaMA 3) untuk konfirmasi:
 * - Apakah ini benar leaked secret atau false positive?
 * - Risk level: CRITICAL / HIGH / MEDIUM / NONE
 *
 * Jika GROQ_API_KEY tidak di-set, fallback ke deterministic mode.
 */

// ── Types ────────────────────────────────────────────────────────

export interface LLMClassifyResult {
  isLeak: boolean;
  riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "NONE";
  reasoning: string;
  mode: "llm" | "fallback";
}

// ── Main Classifier ──────────────────────────────────────────────

export async function classifyWithLLM(
  matchedValue: string,
  secretType: string,
  context: string
): Promise<LLMClassifyResult> {
  const apiKey = process.env.GROQ_API_KEY;

  if (!apiKey) {
    return fallbackClassify(secretType);
  }

  try {
    console.log(`   🤖 LLM classifying secret candidate (Groq)...`);

    // Mask secret value — hanya kirim prefix + panjang, bukan full value
    const maskedValue = maskSecret(matchedValue);

    const prompt = buildPrompt(maskedValue, secretType, context);

    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: "llama-3.3-70b-versatile",
        messages: [
          {
            role: "system",
            content:
              "You are a security analyst. Classify leaked secrets in code commits. " +
              "Respond ONLY in valid JSON format: " +
              '{"isLeak": boolean, "riskLevel": "CRITICAL"|"HIGH"|"MEDIUM"|"NONE", "reasoning": "short explanation"}',
          },
          { role: "user", content: prompt },
        ],
        temperature: 0,
        max_tokens: 200,
      }),
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error(`   LLM API error (${response.status}): ${errText}`);
      return fallbackClassify(secretType);
    }

    const data = (await response.json()) as {
      choices?: { message?: { content?: string } }[];
    };

    const content = data.choices?.[0]?.message?.content?.trim();
    if (!content) {
      return fallbackClassify(secretType);
    }

    // Parse JSON response dari LLM
    const parsed = JSON.parse(content) as {
      isLeak: boolean;
      riskLevel: string;
      reasoning: string;
    };

    const validRiskLevels = ["CRITICAL", "HIGH", "MEDIUM", "NONE"] as const;
    const riskLevel = validRiskLevels.includes(
      parsed.riskLevel as (typeof validRiskLevels)[number]
    )
      ? (parsed.riskLevel as LLMClassifyResult["riskLevel"])
      : "MEDIUM";

    return {
      isLeak: parsed.isLeak,
      riskLevel,
      reasoning: parsed.reasoning || "No reasoning provided",
      mode: "llm",
    };
  } catch (error: any) {
    console.error(`   LLM classification error: ${error.message}`);
    return fallbackClassify(secretType);
  }
}

// ── Prompt Builder ───────────────────────────────────────────────

function buildPrompt(
  maskedValue: string,
  secretType: string,
  context: string
): string {
  return `A code commit contains a potential leaked secret.

Secret type detected: ${secretType}
Masked value: ${maskedValue}
Context (surrounding code):
\`\`\`
${context.slice(0, 500)}
\`\`\`

Analyze:
1. Is this a REAL leaked secret or a false positive (test key, placeholder, example)?
2. What is the risk level?

Risk level criteria:
- CRITICAL: Production API key for payment/AI services (OpenAI, Stripe, AWS)
- HIGH: Access tokens for code repos or CI/CD (GitHub, GitLab)
- MEDIUM: Internal or development keys with limited scope
- NONE: Clearly a test key, example, or placeholder

Respond in JSON only.`;
}

// ── Secret Masking ───────────────────────────────────────────────
// Jangan kirim full secret ke LLM — hanya prefix + metadata

function maskSecret(value: string): string {
  if (value.length <= 8) return value;
  const prefix = value.substring(0, 7);
  return `${prefix}...*** (${value.length} chars total)`;
}

// ── Fallback (tanpa LLM) ────────────────────────────────────────
// Digunakan jika GROQ_API_KEY tidak di-set atau API error

function fallbackClassify(secretType: string): LLMClassifyResult {
  const riskMap: Record<string, LLMClassifyResult["riskLevel"]> = {
    openai: "CRITICAL",
    aws: "CRITICAL",
    github: "HIGH",
    jwt: "HIGH",
    generic: "MEDIUM",
  };

  const riskLevel = riskMap[secretType] || "MEDIUM";

  console.log(`   🤖 LLM fallback mode — classified as ${riskLevel}`);

  return {
    isLeak: true,
    riskLevel,
    reasoning: `Deterministic classification based on secret type: ${secretType}`,
    mode: "fallback",
  };
}
