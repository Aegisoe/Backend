/**
 * CRE Workflow Trigger Client
 *
 * Mengirim request ke Chainlink CRE trigger endpoint
 * untuk memulai aegisoe-confidential-incident-response workflow.
 *
 * CRE_TRIGGER_URL akan diberikan oleh Dev 2 setelah workflow deployed.
 * Untuk development, gunakan mock mode.
 */

// ── Types ────────────────────────────────────────────────────────

export interface CRETriggerPayload {
  secretId: string;   // bytes32 hex string
  repo: string;       // "owner/repo-name"
  commitSha: string;  // full commit SHA
  secretType: string; // "openai" | "aws" | "github" | "generic"
  vaultUrl: string;   // HashiCorp Vault URL
}

export interface CRETriggerResult {
  success: boolean;
  jobId?: string;
  error?: string;
}

// ── Main Trigger Function ────────────────────────────────────────

export async function triggerCREWorkflow(
  payload: CRETriggerPayload
): Promise<CRETriggerResult> {
  const creUrl = process.env.CRE_TRIGGER_URL;

  // MOCK MODE: jika CRE_TRIGGER_URL belum di-set (Dev 2 belum selesai)
  if (!creUrl || creUrl === "https://your-cre-endpoint/scan") {
    return handleMockMode(payload);
  }

  try {
    console.log(`📡 Sending to CRE: ${creUrl}`);
    console.log(`   SecretId : ${payload.secretId}`);
    console.log(`   Repo     : ${payload.repo}`);
    console.log(`   Type     : ${payload.secretType}`);

    const response = await fetch(creUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        // Input sesuai workflow.yaml inputs
        secretId:   payload.secretId,
        repo:       payload.repo,
        commitSha:  payload.commitSha,
        secretType: payload.secretType,
        vaultUrl:   payload.vaultUrl,
        owner:      payload.repo.split("/")[0],
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`CRE returned ${response.status}: ${errorText}`);
      return {
        success: false,
        error: `CRE returned ${response.status}: ${errorText}`,
      };
    }

    const data = await response.json() as { jobId?: string; id?: string };

    return {
      success: true,
      jobId: data.jobId || data.id || "unknown",
    };
  } catch (error: any) {
    console.error("CRE trigger error:", error.message);
    return {
      success: false,
      error: error.message,
    };
  }
}

// ── Mock Mode ────────────────────────────────────────────────────
// Digunakan selama Dev 2 belum selesai setup CRE workflow.
// Simulasikan response CRE agar flow backend tetap bisa ditest.

function handleMockMode(payload: CRETriggerPayload): CRETriggerResult {
  console.log("\n⚠️  CRE MOCK MODE ACTIVE");
  console.log("   (Set CRE_TRIGGER_URL di .env untuk mode production)");
  console.log("\n   Simulating CRE workflow execution:");
  console.log(`   ① fetch_commit        → OK (mock)`);
  console.log(`   ② detect_secret       → FOUND: ${payload.secretType}`);
  console.log(`   ③ classify_risk       → CRITICAL (mock)`);
  console.log(`   ④ policy_decision     → shouldRotate: true`);
  console.log(`   ⑤ generate_new_key    → OK (mock)`);
  console.log(`   ⑥ revoke_old_key      → OK (mock)`);
  console.log(`   ⑦ update_vault        → OK (mock)`);
  console.log(`   ⑧ generate_commitments → OK (mock)`);
  console.log(`   ⑨ submit_incident     → TX: 0xMOCK...`);
  console.log(`   ⑩ submit_rotation     → TX: 0xMOCK...`);
  console.log(`\n   ✅ Mock workflow completed for: ${payload.repo}`);

  return {
    success: true,
    jobId: `mock-${Date.now()}`,
  };
}
