/**
 * AEGISOE — CRE Incident Response Workflow
 *
 * Dieksekusi di dalam Chainlink TEE (Confidential Runtime Environment).
 * Workflow ini menangani rotasi secret yang bocor secara otomatis:
 *
 *   Step 1: Decode trigger payload dari Backend
 *   Step 2: Load secrets dari CRE secrets store
 *   Step 3: Generate incident commitment (SHA-256 di dalam TEE = tamper-proof)
 *   Step 4: Revoke GitHub token via ConfidentialHTTP (jika secretType = "github")
 *   Step 5: Rotate secret di HashiCorp Vault via ConfidentialHTTP
 *   Step 6: Callback ke Backend dengan commitments untuk on-chain tx
 *   Step 7: Return summary result
 *
 * On-chain write (AegisoeRegistry.recordIncident / recordRotation) dilakukan
 * oleh Backend setelah menerima callback — karena AegisoeRegistry menggunakan
 * standard Solidity functions, bukan CRE report interface.
 */

import {
  ConfidentialHTTPClient,
  HTTPCapability,
  handler,
  Runner,
  type HTTPPayload,
  type Runtime,
} from "@chainlink/cre-sdk";

// ── Config type ───────────────────────────────────────────────────────────────
// Nilai di config.staging.json / config.production.json

export type Config = {
  contractAddress: string;    // AegisoeRegistry address di Sepolia
  backendCallbackUrl: string; // Backend /cre-callback endpoint
};

// ── Trigger payload (dikirim oleh Backend) ────────────────────────────────────

interface TriggerPayload {
  secretType: string;   // "openai" | "aws" | "github" | "jwt" | "generic"
  matchedValue: string; // leaked secret value (dari regexScanner)
  riskLevel: string;    // "CRITICAL" | "HIGH" | "MEDIUM"
  repo: string;         // "owner/repo-name"
  commitSha: string;    // full commit SHA
  secretId: string;     // keccak256(secretType + "_" + repo) — dihitung Backend
}

// ── SHA-256 helper (jalankan di dalam TEE) ────────────────────────────────────

async function sha256Hex(value: string): Promise<string> {
  const data = new TextEncoder().encode(value);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── riskLevel string → uint8 (sesuai AegisoeRegistry RiskLevel enum) ─────────
// NONE=0 (SC revert!), MEDIUM=1, HIGH=2, CRITICAL=3

function riskToUint(riskLevel: string): number {
  const map: Record<string, number> = {
    medium: 1,
    high: 2,
    critical: 3,
  };
  return map[riskLevel.toLowerCase()] ?? 1; // fallback ke MEDIUM, JANGAN 0
}

// ── Main workflow handler ─────────────────────────────────────────────────────

// ConfidentialHTTPClient is instantiated once (instance method, not static)
const confidentialHttp = new ConfidentialHTTPClient();

export const onHTTPTrigger = async (
  runtime: Runtime<Config>,
  triggerOutput: HTTPPayload
): Promise<string> => {
  // ── Step 1: Decode trigger payload ──────────────────────────────────────────
  const payloadText = new TextDecoder().decode(triggerOutput.input);
  const payload = JSON.parse(payloadText) as TriggerPayload;

  runtime.log(`🔍 AEGISOE incident: ${payload.secretType} in ${payload.repo}`);
  runtime.log(`   SecretId  : ${payload.secretId}`);
  runtime.log(`   RiskLevel : ${payload.riskLevel}`);
  runtime.log(`   CommitSHA : ${payload.commitSha.slice(0, 12)}...`);

  // ── Step 2: Load secrets dari CRE secrets store ──────────────────────────────
  // Secrets didaftarkan via: cre secrets set --secret-name <NAME> --value <val>
  const githubToken    = runtime.getSecret({ id: "GITHUB_TOKEN" }).result().value;
  const vaultToken     = runtime.getSecret({ id: "VAULT_ADMIN_TOKEN" }).result().value;
  const callbackSecret = runtime.getSecret({ id: "BACKEND_CALLBACK_SECRET" }).result().value;
  const vaultUrl       = runtime.getSecret({ id: "VAULT_URL" }).result().value;

  runtime.log("🔐 Secrets loaded from CRE secrets store");

  // ── Step 3: Generate incident commitment di dalam TEE ───────────────────────
  // Hash dari nilai secret + commit SHA = bukti bahwa TEE melihat secret ini
  const incidentRaw        = `${payload.matchedValue}:${payload.commitSha}:${payload.repo}`;
  const incidentHash       = await sha256Hex(incidentRaw);
  const incidentCommitment = `0x${incidentHash}`;
  runtime.log(`📝 Incident commitment: ${incidentCommitment.slice(0, 18)}...`);

  // ── Step 4: Revoke GitHub token (hanya jika secretType = "github") ───────────
  let githubRevoked = false;
  if (payload.secretType === "github" && githubToken) {
    runtime.log("🔑 Revoking GitHub token via Confidential HTTP...");
    const revokeResp = confidentialHttp.sendRequest(runtime, {
      request: {
        url: `https://api.github.com/applications/${payload.matchedValue}/tokens`,
        method: "DELETE",
        multiHeaders: {
          "Authorization":        { values: [`Bearer ${githubToken}`] },
          "Accept":               { values: ["application/vnd.github+json"] },
          "X-GitHub-Api-Version": { values: ["2022-11-28"] },
          "User-Agent":           { values: ["AEGISOE-CRE/1.0"] },
        },
      },
    }).result();
    githubRevoked = revokeResp.statusCode === 204;
    runtime.log(`   GitHub revoke: ${githubRevoked ? "✅ 204" : `⚠️ ${revokeResp.statusCode}`}`);
  }

  // ── Step 5: Rotate secret di HashiCorp Vault ────────────────────────────────
  let rotated       = false;
  let newCommitment = incidentCommitment; // default sama jika rotasi gagal / tidak ada Vault

  if (vaultToken && vaultUrl) {
    runtime.log("🔄 Rotating secret in Vault via Confidential HTTP...");

    // Buat nilai secret baru di dalam TEE
    const tsMs         = runtime.now().getTime().toString();
    const newSecretRaw = `rotated_${payload.commitSha.slice(0, 16)}_${tsMs}`;
    const newSecretHash = await sha256Hex(newSecretRaw);
    newCommitment = `0x${newSecretHash}`;

    const vaultPath = `secret/data/aegisoe/${payload.secretType}/${payload.repo.replace("/", "_")}`;
    const vaultResp = confidentialHttp.sendRequest(runtime, {
      request: {
        url: `${vaultUrl}/v1/${vaultPath}`,
        method: "POST",
        multiHeaders: {
          "X-Vault-Token": { values: [vaultToken] },
          "Content-Type":  { values: ["application/json"] },
        },
        bodyString: JSON.stringify({
          data: {
            value:               newSecretRaw, // nilai baru (hanya tersimpan di Vault)
            rotated_at:          runtime.now().toISOString(),
            previous_commitment: incidentCommitment,
            new_commitment:      newCommitment,
            repo:                payload.repo,
            secret_type:         payload.secretType,
          },
        }),
      },
    }).result();

    rotated = vaultResp.statusCode >= 200 && vaultResp.statusCode < 300;
    runtime.log(`   Vault rotation: ${rotated ? "✅ success" : `⚠️ status ${vaultResp.statusCode}`}`);
  }

  // ── Step 6: Callback ke Backend dengan commitments ──────────────────────────
  // Backend akan submit on-chain tx: AegisoeRegistry.recordIncident + recordRotation
  runtime.log("📡 Sending callback to Backend for on-chain submission...");

  const callbackBody = {
    secretId:           payload.secretId,
    incidentCommitment,
    newCommitment,
    riskLevel:          riskToUint(payload.riskLevel),
    repo:               payload.repo,
    rotated,
    githubRevoked,
    processedAt:        runtime.now().toISOString(),
  };

  const config = runtime.config;
  const callbackResp = confidentialHttp.sendRequest(runtime, {
    request: {
      url: config.backendCallbackUrl,
      method: "POST",
      multiHeaders: {
        "Content-Type": { values: ["application/json"] },
        "X-CRE-Secret": { values: [callbackSecret] },
      },
      bodyString: JSON.stringify(callbackBody),
    },
  }).result();

  const callbackOk = callbackResp.statusCode >= 200 && callbackResp.statusCode < 300;
  runtime.log(`   Callback: ${callbackOk ? "✅" : "⚠️"} status ${callbackResp.statusCode}`);

  // ── Step 7: Return result ───────────────────────────────────────────────────
  const result = {
    success:          callbackOk,
    secretId:         payload.secretId,
    incidentCommitment,
    newCommitment,
    riskLevel:        payload.riskLevel,
    riskLevelUint:    riskToUint(payload.riskLevel),
    repo:             payload.repo,
    rotated,
    githubRevoked,
    onChainSubmitted: callbackOk,
    processedAt:      callbackBody.processedAt,
  };

  runtime.log(`✅ AEGISOE workflow complete — rotated=${rotated} onChain=${callbackOk}`);
  return JSON.stringify(result);
};

// ── Workflow initializer ──────────────────────────────────────────────────────

export const initWorkflow = (config: Config) => {
  const http = new HTTPCapability();
  return [
    handler(http.trigger({}), onHTTPTrigger),
  ];
};

// ── Main entry point ──────────────────────────────────────────────────────────

export async function main() {
  const runner = await Runner.newRunner<Config>();
  await runner.run(initWorkflow);
}
