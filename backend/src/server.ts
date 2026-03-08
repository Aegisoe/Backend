import express, { Express, Request, Response, NextFunction } from "express";
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

const app: Express = express();
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

// ── Pending CRE payloads (untuk CRE simulate lokal) ─────────────
interface CREPendingPayload {
  secretType: string;
  matchedValue: string;
  riskLevel: string;
  repo: string;
  commitSha: string;
  secretId: string;
  createdAt: string;
}

const crePendingQueue: CREPendingPayload[] = [];

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

// ── GitHub API: fetch real commit diff ──────────────────────────

async function fetchCommitDiff(
  repo: string,
  commitSha: string
): Promise<string | null> {
  const token = process.env.GITHUB_API_TOKEN;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.diff",
    "User-Agent": "AEGISOE-Backend/1.0",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  try {
    const url = `https://api.github.com/repos/${repo}/commits/${commitSha}`;
    console.log(`   📡 Fetching diff: GET ${url}`);

    const response = await fetch(url, { headers });

    if (!response.ok) {
      console.warn(`   ⚠️  GitHub API ${response.status} — falling back to metadata scan`);
      return null;
    }

    const diff = await response.text();
    console.log(`   ✅ Got real diff (${diff.length} chars)`);
    return diff;
  } catch (err: any) {
    console.warn(`   ⚠️  GitHub API error: ${err.message} — falling back to metadata scan`);
    return null;
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

// ── CRE Pending Queue — untuk CRE simulate lokal ────────────────
// GET: ambil payload terbaru untuk di-feed ke `cre workflow simulate`
app.get("/cre/pending", (_req: Request, res: Response) => {
  if (crePendingQueue.length === 0) {
    res.json({ pending: 0, payload: null });
    return;
  }
  // Ambil yang paling baru (LIFO) tanpa hapus — bisa dipakai berulang
  const latest = crePendingQueue[crePendingQueue.length - 1];
  res.json({ pending: crePendingQueue.length, payload: latest });
});

// DELETE: pop & consume satu payload dari queue
app.delete("/cre/pending", (_req: Request, res: Response) => {
  const consumed = crePendingQueue.shift();
  res.json({
    consumed: consumed || null,
    remaining: crePendingQueue.length,
  });
});

// ── Demo Trigger — untuk juri / testing tanpa GitHub webhook ────
// Simulasikan push event dengan leaked secret tanpa perlu HMAC signature
app.post("/demo/trigger", async (req: Request, res: Response) => {
  const {
    secretType = "openai",
    secretValue = "sk-proj-DEMO1234567890abcdefghijklmnopqrstuvwxyz",
    repo = "Aegisoe/demo-repo",
    commitSha = crypto.randomBytes(20).toString("hex"),
    creSimulate = false, // true = hanya detect + queue, biarkan CRE simulate handle on-chain
  } = req.body || {};

  console.log(`\n🎯 DEMO TRIGGER received`);
  console.log(`   SecretType  : ${secretType}`);
  console.log(`   Repo        : ${repo}`);
  console.log(`   CommitSha   : ${commitSha}`);
  console.log(`   CRE Simulate: ${creSimulate ? "ON — skip mock CRE, wait for CRE callback" : "OFF — mock CRE + on-chain"}`);

  // Langsung jalankan pipeline detection → on-chain (skip HMAC)
  const simulatedDiff = `
    commit: ${commitSha}
    message: feat: add API integration
    files: config/secrets.js
    added_lines: const API_KEY = "${secretValue}";
  `;

  res.status(200).json({
    message: creSimulate
      ? "Demo triggered — detection only, waiting for CRE simulate callback..."
      : "Demo triggered — processing pipeline...",
    commitSha,
    secretType,
    repo,
    creSimulate,
  });

  // Jalankan async pipeline
  processDemoTrigger(simulatedDiff, repo, commitSha, creSimulate).catch((err) => {
    console.error("❌ Demo trigger error:", err.message);
  });
});

async function processDemoTrigger(
  diff: string,
  repo: string,
  commitSha: string,
  creSimulate: boolean = false
): Promise<void> {
  // Step 1-2: Regex + Entropy scan
  const scanResult = scanDiffForSecrets(diff);

  if (!scanResult.hasSecret) {
    console.log("❌ Demo: no secret detected in simulated diff");
    return;
  }

  console.log(`\n🚨 DEMO — SECRET DETECTED`);
  console.log(`   Step 1  : Regex match — ${scanResult.secretType}`);
  console.log(`   Step 2  : Entropy — ${scanResult.entropy?.toFixed(2)} bits/char`);

  // Step 3: LLM Classification
  const llmResult = await classifyWithLLM(
    scanResult.matchedValue || "",
    scanResult.secretType || "generic",
    diff
  );

  console.log(`   Step 3  : LLM — ${llmResult.riskLevel} (${llmResult.mode})`);

  // Step 4: Generate secretId
  const secretId = encodeSecretId(scanResult.secretType || "generic", repo);

  // Step 5: Record incident
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

  // Step 6: Push payload ke CRE pending queue (untuk cre simulate lokal)
  const crePayload: CREPendingPayload = {
    secretType: scanResult.secretType || "generic",
    matchedValue: scanResult.matchedValue || "",
    riskLevel: llmResult.riskLevel,
    repo,
    commitSha,
    secretId,
    createdAt: new Date().toISOString(),
  };
  crePendingQueue.push(crePayload);
  console.log(`📋 CRE payload queued — ${crePendingQueue.length} pending`);
  console.log(`   Fetch with: GET /cre/pending`);

  // ── creSimulate mode: STOP HERE — CRE simulate akan handle via /cre-callback ──
  if (creSimulate) {
    console.log(`\n⏸️  CRE Simulate mode — waiting for CRE callback to handle on-chain...`);
    console.log(`   Run: cre workflow simulate ./incident-response --http-payload @payload.json --target staging-settings`);
    incident.status = "rotating";
    incident.creTriggered = true;
    return;
  }

  // Step 7: Juga trigger CRE (real atau mock)
  console.log(`\n🔄 Triggering CRE workflow...`);
  incident.status = "rotating";

  const creResult = await triggerCREWorkflow({
    secretId,
    repo,
    commitSha,
    secretType: scanResult.secretType || "generic",
    vaultUrl: "http://localhost:8200",
  });

  if (creResult.success) {
    incident.creTriggered = true;

    // Mock mode: submit on-chain langsung (CRE tidak akan callback)
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

      incident.status = "rotated";
      console.log(`\n✅ DEMO complete (mock) — check Sepolia Etherscan & Frontend`);
    } else {
      // Real CRE mode — on-chain via /cre-callback
      console.log(`✅ CRE triggered — waiting for /cre-callback`);
    }
  } else {
    console.error(`❌ CRE trigger failed: ${creResult.error}`);
  }
}

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
  // ── Fetch real diff from GitHub API ──────────────────────────
  // Coba ambil diff asli dari GitHub API (butuh isi file, bukan cuma metadata)
  let fullDiff: string | null = null;

  for (const commit of payload.commits || []) {
    const realDiff = await fetchCommitDiff(repo, commit.id || commitSha);
    if (realDiff) {
      fullDiff = (fullDiff || "") + "\n" + realDiff;
    }
  }

  // Fallback: jika GitHub API gagal, gunakan metadata dari webhook payload
  if (!fullDiff) {
    console.log("   ℹ️  Using webhook metadata fallback (no GitHub API diff)");
    const metaDiffs: string[] = [];
    for (const commit of payload.commits || []) {
      const addedFiles = commit.added || [];
      const modifiedFiles = commit.modified || [];
      const allFiles = [...addedFiles, ...modifiedFiles];
      metaDiffs.push(`
        commit: ${commit.id}
        message: ${commit.message}
        files: ${allFiles.join(", ")}
      `);
    }
    fullDiff = metaDiffs.join("\n");
  }

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
  console.log(`   Port      : ${PORT}`);
  console.log(`   Health    : http://localhost:${PORT}/health`);
  console.log(`   Webhook   : http://localhost:${PORT}/webhook`);
  console.log(`   Demo      : POST http://localhost:${PORT}/demo/trigger`);
  console.log(`   Incidents : http://localhost:${PORT}/incidents`);
  console.log(`\n   ⚡ Waiting for webhooks or demo triggers...\n`);
});

export default app;
