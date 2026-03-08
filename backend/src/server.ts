import express, { Request, Response, NextFunction } from "express";
import * as crypto from "crypto";
import * as dotenv from "dotenv";
import { scanDiffForSecrets } from "./detection/regexScanner";
import { classifyWithLLM } from "./detection/llmClassifier";
import { triggerCREWorkflow } from "./cre/triggerWorkflow";
import { shouldAutoRotate } from "./policy/policyChecker";
import { encodeSecretId } from "./aegisoeTypes";
import {
  recordIncidentOnChain,
  recordRotationOnChain,
  generateMockCommitment,
} from "./blockchain/onChainWriter";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ── In-memory incident log (untuk demo) ─────────────────────────
interface Incident {
  id: string;
  repo: string;
  commitSha: string;
  secretType: string;
  status: "detected" | "rotating" | "rotated" | "skipped";
  riskLevel?: string;
  detectedAt: string;
  creTriggered: boolean;
}

const incidents: Incident[] = [];

// ── Middleware ───────────────────────────────────────────────────

// Raw body parser khusus untuk webhook (HMAC butuh raw body)
app.use(
  "/webhook",
  express.raw({ type: "application/json" })
);

// JSON parser untuk endpoint lain
app.use(express.json());

// ── HMAC Verification ───────────────────────────────────────────

function verifyGitHubSignature(
  rawBody: Buffer,
  signature: string | undefined
): boolean {
  if (!signature) return false;

  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) {
    console.error("GITHUB_WEBHOOK_SECRET not set");
    return false;
  }

  const hmac = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest("hex");

  const expectedSignature = `sha256=${hmac}`;

  // Gunakan timingSafeEqual untuk mencegah timing attack
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  } catch {
    return false;
  }
}

// ── Routes ───────────────────────────────────────────────────────

// Health check
app.get("/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    service: "AEGISOE Backend",
    timestamp: new Date().toISOString(),
    onChain: !!process.env.OPERATOR_PRIVATE_KEY,
    creMode: process.env.CRE_TRIGGER_URL ? "real" : "mock",
  });
});

// ── CRE Callback — dipanggil oleh CRE setelah workflow selesai ───
// CRE mengirim commitments → Backend submit on-chain tx
app.post("/cre-callback", async (req: Request, res: Response) => {
  // Verifikasi X-CRE-Secret header
  const secret = process.env.CRE_CALLBACK_SECRET;
  if (secret && req.headers["x-cre-secret"] !== secret) {
    console.warn("❌ CRE callback rejected — invalid X-CRE-Secret");
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const {
    secretId,
    incidentCommitment,
    newCommitment,
    riskLevel,
    repo,
    rotated,
  } = req.body as {
    secretId: string;
    incidentCommitment: string;
    newCommitment: string;
    riskLevel: number;
    repo: string;
    rotated: boolean;
    githubRevoked: boolean;
    processedAt: string;
  };

  console.log(`\n📥 CRE callback received`);
  console.log(`   SecretId  : ${secretId}`);
  console.log(`   Rotated   : ${rotated}`);

  res.status(200).json({ message: "Callback received, submitting on-chain..." });

  // Submit on-chain secara async
  submitOnChain({ secretId, incidentCommitment, newCommitment, riskLevel, repo, rotated }).catch(
    (err) => console.error("❌ On-chain submission failed:", err.message)
  );
});

// Incident log — untuk frontend
app.get("/incidents", (_req: Request, res: Response) => {
  res.json({
    total: incidents.length,
    incidents: incidents.slice().reverse(), // newest first
  });
});

// ── MAIN: GitHub Webhook ─────────────────────────────────────────
app.post("/webhook", async (req: Request, res: Response) => {
  const rawBody = req.body as Buffer;
  const signature = req.headers["x-hub-signature-256"] as string;
  const eventType = req.headers["x-github-event"] as string;

  // 1. Verifikasi HMAC signature
  if (!verifyGitHubSignature(rawBody, signature)) {
    console.warn("❌ Invalid webhook signature — request rejected");
    res.status(401).json({ error: "Invalid signature" });
    return;
  }

  // 2. Parse payload
  let payload: any;
  try {
    payload = JSON.parse(rawBody.toString());
  } catch {
    res.status(400).json({ error: "Invalid JSON payload" });
    return;
  }

  // 3. Hanya proses event 'push'
  if (eventType !== "push") {
    console.log(`ℹ️  Event '${eventType}' ignored — only processing 'push'`);
    res.status(200).json({ message: "Event ignored" });
    return;
  }

  const repo = payload.repository?.full_name || "unknown/repo";
  const commitSha = payload.after || "unknown";
  const commits = payload.commits || [];

  console.log(`\n📦 Push event received`);
  console.log(`   Repo    : ${repo}`);
  console.log(`   Commit  : ${commitSha}`);
  console.log(`   Commits : ${commits.length}`);

  // 4. Respond ke GitHub cepat (GitHub timeout 10 detik)
  res.status(200).json({ message: "Webhook received, processing..." });

  // 5. Process secara async (tidak block response)
  processWebhook(repo, commitSha, payload).catch((err) => {
    console.error("❌ Error processing webhook:", err);
  });
});

// ── Async Processor ──────────────────────────────────────────────

async function processWebhook(
  repo: string,
  commitSha: string,
  payload: any
): Promise<void> {
  // Kumpulkan semua diff dari commits
  const allDiffs: string[] = [];

  for (const commit of payload.commits || []) {
    // Gabungkan added + modified files sebagai simple text scan
    const addedFiles = commit.added || [];
    const modifiedFiles = commit.modified || [];
    const allFiles = [...addedFiles, ...modifiedFiles];

    // Untuk demo: gunakan commit message + file names sebagai simulasi diff
    // Di production: fetch actual diff via GitHub API
    const simulatedDiff = `
      commit: ${commit.id}
      message: ${commit.message}
      files: ${allFiles.join(", ")}
      added_lines: ${commit.added?.join(" ") || ""}
    `;
    allDiffs.push(simulatedDiff);
  }

  const fullDiff = allDiffs.join("\n");

  // 6. Pre-filter: quick regex scan sebelum trigger CRE
  const scanResult = scanDiffForSecrets(fullDiff);

  if (!scanResult.hasSecret) {
    console.log("✅ No secrets detected in diff — skipping");
    return;
  }

  console.log(`\n🚨 SECRET DETECTED`);
  console.log(`   Step 1  : Regex match — ${scanResult.secretType}`);
  console.log(`   Step 2  : Entropy — ${scanResult.entropy?.toFixed(2)} bits/char`);

  // 7. LLM Classification (Step 3) — final check sebelum trigger CRE
  const llmResult = await classifyWithLLM(
    scanResult.matchedValue || "",
    scanResult.secretType || "generic",
    fullDiff
  );

  console.log(`   Step 3  : LLM — ${llmResult.riskLevel} (${llmResult.mode})`);
  console.log(`   Reason  : ${llmResult.reasoning}`);

  // Jika LLM bilang bukan leak → skip
  if (!llmResult.isLeak) {
    console.log("✅ LLM classified as NOT a leak — skipping");
    return;
  }

  // 8. Generate secretId — keccak256 (match SC & CRE Step 8)
  const secretId = encodeSecretId(scanResult.secretType || "generic", repo);

  // 9. Catat incident
  const incident: Incident = {
    id: commitSha.substring(0, 8),
    repo,
    commitSha,
    secretType: scanResult.secretType || "unknown",
    status: "detected",
    riskLevel: llmResult.riskLevel,
    detectedAt: new Date().toISOString(),
    creTriggered: false,
  };
  incidents.push(incident);

  // 10. Policy check — gunakan risk level dari LLM
  const policy = shouldAutoRotate(scanResult.secretType || "generic");

  if (!policy.autoRotate) {
    console.log(`⚠️  Policy: manual approval required for ${scanResult.secretType}`);
    incident.status = "skipped";
    return;
  }

  // 10. Trigger CRE workflow
  console.log(`\n🔄 Triggering Chainlink CRE workflow...`);
  incident.status = "rotating";

  const creResult = await triggerCREWorkflow({
    secretId,
    repo,
    commitSha,
    secretType: scanResult.secretType || "generic",
    vaultUrl: "http://localhost:8200", // dari .env di production
  });

  if (creResult.success) {
    incident.status = "rotated";
    incident.creTriggered = true;
    console.log(`✅ CRE workflow triggered successfully`);
    console.log(`   Job ID : ${creResult.jobId}`);

    // Mock mode: CRE tidak akan callback → submit on-chain langsung dengan mock commitments
    const isMockMode =
      !process.env.CRE_TRIGGER_URL ||
      process.env.CRE_TRIGGER_URL === "https://your-cre-endpoint/scan" ||
      creResult.jobId?.startsWith("mock-");

    if (isMockMode) {
      const mockIncidentCommitment = generateMockCommitment(secretId, commitSha, "incident");
      const mockNewCommitment      = generateMockCommitment(secretId, commitSha, "rotation");
      const riskUint               = llmResult.riskLevel === "CRITICAL" ? 3
                                    : llmResult.riskLevel === "HIGH"     ? 2
                                    : 1;
      await submitOnChain({
        secretId,
        incidentCommitment: mockIncidentCommitment,
        newCommitment: mockNewCommitment,
        riskLevel: riskUint,
        repo,
        rotated: true,
      });
    }
    // Real CRE mode: on-chain submission akan terjadi via /cre-callback
  } else {
    console.error(`❌ CRE trigger failed: ${creResult.error}`);
  }
}

// ── Shared on-chain submission logic ────────────────────────────

async function submitOnChain(params: {
  secretId: string;
  incidentCommitment: string;
  newCommitment: string;
  riskLevel: number;
  repo: string;
  rotated: boolean;
}): Promise<void> {
  if (!process.env.OPERATOR_PRIVATE_KEY) {
    console.warn("⚠️  OPERATOR_PRIVATE_KEY not set — skipping on-chain submission");
    console.warn("   Set OPERATOR_PRIVATE_KEY in Railway to enable on-chain recording");
    return;
  }

  try {
    const incidentTxHash = await recordIncidentOnChain({
      secretId: params.secretId,
      incidentCommitment: params.incidentCommitment,
      riskLevel: params.riskLevel,
      repo: params.repo,
    });
    console.log(`\n✅ Incident recorded on-chain: ${incidentTxHash}`);

    if (params.rotated) {
      const rotationTxHash = await recordRotationOnChain({
        secretId: params.secretId,
        oldCommitment: params.incidentCommitment,
        newCommitment: params.newCommitment,
      });
      console.log(`✅ Rotation recorded on-chain: ${rotationTxHash}`);
    }
  } catch (err: any) {
    console.error(`❌ On-chain submission error: ${err.message}`);
  }
}

// ── Start Server ─────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🛡️  AEGISOE Backend running`);
  console.log(`   Port    : ${PORT}`);
  console.log(`   Health  : http://localhost:${PORT}/health`);
  console.log(`   Webhook : http://localhost:${PORT}/webhook`);
  console.log(`   Incidents: http://localhost:${PORT}/incidents`);
  console.log(`\n   ⚡ Waiting for GitHub webhooks...\n`);
});

export default app;
