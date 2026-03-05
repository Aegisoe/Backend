# 🛡️ AEGISOE — BLUEPRINT FINAL v5
## Confidential Security Automation Network

**Version:** 5.0 (Hackathon Final — Implementation Ready)
**Date:** March 2026
**Track:** Chainlink Hackathon — Privacy Track
**Status:** Build-Ready

---

# A. POSITIONING

## Judul Resmi
**AEGISOE — Confidential Security Automation Network**

## Tagline
> "The first verifiable on-chain incident response engine for leaked secrets."

## One-liner untuk Juri
> AEGISOE uses Chainlink CRE as its orchestration brain — every sensitive operation runs inside a TEE enclave via Confidential HTTP, and every incident is permanently proven on-chain without ever exposing a single secret.

## Kenapa Ini Menang di Privacy Track?
Chainlink ingin melihat proyek yang:
- Menggunakan **Confidential HTTP** secara nyata (bukan hanya menyebut)
- Menjadikan **CRE sebagai orchestration layer**, bukan sekadar tool
- Memiliki **offchain privacy + onchain auditability** secara bersamaan
- Menyelesaikan **masalah nyata** dengan privacy-preserving workflow

AEGISOE memenuhi semua empat kriteria ini.

---

# B. APA YANG BERUBAH DARI v4 ke v5

| Aspek | v4 | v5 |
|---|---|---|
| Posisi CRE | Tool yang dipanggil backend | **Orchestration brain** |
| Detection | Backend only | Pre-filter di backend + **confirm di CRE enclave** |
| LLM classification | Tidak ada | ✅ **Confidential HTTP → OpenAI API** |
| Blockchain events | 1 event (SecretRotated) | ✅ **2 events: IncidentRecorded + SecretRotated** |
| On-chain framing | Rotation log | ✅ **Security incident ledger** |
| Narrative | Secret rotation system | ✅ **Confidential incident response network** |
| Score estimasi | 8.7/10 | **~9.0–9.3/10** |

---

# C. ARSITEKTUR SISTEM LENGKAP

## C.1 Full Flow

```
[DEVELOPER]
git push → commit berisi "sk-abc123"
    │
    │ GitHub push event
    ▼
[GITHUB WEBHOOK]
    │
    │ HTTP POST (payload + HMAC signature)
    ▼
[AEGISOE BACKEND — Node.js]
    │ • Verify HMAC signature
    │ • Extract commit SHA + repo info
    │ • Pre-filter: quick regex check
    │ • Jika ada kandidat secret →
    │
    │ POST → CRE trigger endpoint
    ▼
╔═══════════════════════════════════════════════════╗
║        CHAINLINK CRE — TEE ENCLAVE                ║
║                                                   ║
║  ┌─ Step 1: fetch_commit ─────────────────────┐  ║
║  │  Confidential HTTP → GitHub API            │  ║
║  │  Fetch full diff content                   │  ║
║  │  GITHUB_TOKEN tersimpan di CRE secrets     │  ║
║  └────────────────────────────────────────────┘  ║
║  ┌─ Step 2: detect_secret ────────────────────┐  ║
║  │  TEE Compute                               │  ║
║  │  Regex patterns (sk-, AKIA, ghp_)          │  ║
║  │  Shannon entropy > 4.5 bits/char           │  ║
║  │  → hasLeak: true/false                     │  ║
║  └────────────────────────────────────────────┘  ║
║  ┌─ Step 3: classify_risk ────────────────────┐  ║
║  │  Confidential HTTP → OpenAI API            │  ║
║  │  LLM prompt: classify secret risk          │  ║
║  │  → CRITICAL / HIGH / MEDIUM                │  ║
║  │  OPENAI_ADMIN_KEY tersimpan di CRE secrets │  ║
║  └────────────────────────────────────────────┘  ║
║  ┌─ Step 4: policy_decision ──────────────────┐  ║
║  │  TEE Compute                               │  ║
║  │  CRITICAL/HIGH → shouldRotate: true        │  ║
║  │  MEDIUM → shouldRotate: false              │  ║
║  └────────────────────────────────────────────┘  ║
║  ┌─ Step 5: generate_new_key ─────────────────┐  ║
║  │  Confidential HTTP → OpenAI API            │  ║
║  │  POST /v1/organization/api_keys            │  ║
║  │  newKey TIDAK PERNAH keluar enclave        │  ║
║  └────────────────────────────────────────────┘  ║
║  ┌─ Step 6: revoke_old_key ───────────────────┐  ║
║  │  Confidential HTTP → OpenAI API            │  ║
║  │  DELETE /v1/organization/api_keys/{id}     │  ║
║  │  Old key immediately invalid               │  ║
║  └────────────────────────────────────────────┘  ║
║  ┌─ Step 7: update_vault ─────────────────────┐  ║
║  │  Confidential HTTP → Vault API             │  ║
║  │  POST new key value ke vault               │  ║
║  │  VAULT_ADMIN_TOKEN di CRE secrets          │  ║
║  └────────────────────────────────────────────┘  ║
║  ┌─ Step 8: generate_commitments ─────────────┐  ║
║  │  TEE Compute                               │  ║
║  │  oldCommitment = keccak256(old + salt)     │  ║
║  │  newCommitment = keccak256(new + salt)     │  ║
║  │  incidentCommit = keccak256(id+repo+ts)   │  ║
║  └────────────────────────────────────────────┘  ║
║  ┌─ Step 9: submit_incident ──────────────────┐  ║
║  │  On-chain Transaction → Sepolia            │  ║
║  │  AegisoeRegistry.recordIncident(...)       │  ║
║  │  → IncidentRecorded event emitted          │  ║
║  └────────────────────────────────────────────┘  ║
║  ┌─ Step 10: submit_rotation ─────────────────┐  ║
║  │  On-chain Transaction → Sepolia            │  ║
║  │  AegisoeRegistry.recordRotation(...)       │  ║
║  │  → SecretRotated event emitted             │  ║
║  └────────────────────────────────────────────┘  ║
╚═══════════════════════════════════════════════════╝
    │
    ▼
[AEGISOE REGISTRY — Sepolia Smart Contract]
    • 2 permanent events on-chain
    • Public queryable
    • Zero secrets stored
    │
    ▼
[AEGISOE FRONTEND]
    • Dashboard: incident status
    • ProofVerifier: query by secretId
    • IncidentLog: full history
```

## C.2 State Before vs After

| Komponen | Sebelum | Sesudah |
|---|---|---|
| GitHub commit | `sk-abc123` (active) | `sk-abc123` (active tapi sudah revoked) |
| OpenAI dashboard | `sk-abc123` = ACTIVE | `sk-abc123` = REVOKED |
| Vault | `OPENAI_KEY = sk-abc123` | `OPENAI_KEY = sk-live-xyz987` |
| Blockchain | No record | `IncidentRecorded` + `SecretRotated` |
| Exposure window | Hours (manual) | < 30 detik |

---

# D. PEMBAGIAN KERJA DETAIL

## D.1 Dev 1 — Backend Engineer

**Tanggung jawab:** Webhook receiver + CRE trigger client

**Day 1 deliverables:**
- `/webhook` endpoint dengan HMAC verification
- Pre-filter regex scanner (cepat, sebelum trigger CRE)
- CRE trigger HTTP client
- Policy config loader

**Day 2 deliverables:**
- Integration test webhook → CRE
- Error handling + retry
- `/incidents` endpoint untuk frontend
- Deploy ke Railway

**File yang dibuat:**
```
backend/src/server.ts
backend/src/detection/regexScanner.ts
backend/src/detection/entropyAnalyzer.ts
backend/src/cre/triggerWorkflow.ts
backend/src/policy/policyChecker.ts
```

**Jika mepet waktu:** Backend bisa diganti script sederhana yang langsung trigger CRE dengan hardcoded input. Demo tetap bisa jalan.

---

## D.2 Dev 2 — CRE Engineer

**Tanggung jawab:** CRE Workflow + CLI simulation + video recording

**Day 1 deliverables:**
- `workflow.yaml` Steps 1–8 selesai
- CLI simulate Steps 1–4 berhasil
- Semua CRE secrets terdaftar

**Day 2 deliverables:**
- `workflow.yaml` Steps 9–10 selesai (butuh contract address dari Dev 3)
- Full workflow simulate SUCCESS
- Video simulation direkam (MANDATORY)
- CRE live deploy dicoba

**File yang dibuat:**
```
cre/workflow.yaml
cre/workflow.test.yaml
cre/secrets.env.example
```

**Dependency kritikal:**
- Contract address dari Dev 3 (dibutuhkan untuk Steps 9–10)
- Dev 3 harus deploy contract **sebelum jam 3 sore hari 1**

**Jika CRE simulate error:**
Common errors dan solusinya:
```
Error: secret not found     → cre secrets set ulang
Error: network timeout      → check Sepolia RPC URL
Error: invalid step type    → cek syntax workflow.yaml
Error: condition syntax     → gunakan == bukan ===
```

---

## D.3 Dev 3 — Smart Contract + Frontend

**Tanggung jawab:** AegisoeRegistry.sol + ProofVerifier UI

**Day 1 deliverables:**
- `AegisoeRegistry.sol` dengan `recordIncident` + `recordRotation`
- Unit tests passing
- Deployed ke Sepolia (kirim address ke Dev 2 ASAP)
- Verified di Etherscan
- React + Tailwind + wagmi setup
- ProofVerifier page skeleton

**Day 2 deliverables:**
- ProofVerifier: query `getIncidentHistory` + `getRotationHistory`
- Dashboard: incident status table
- IncidentLog: live data dari backend
- Deploy ke Vercel
- Bantu record demo video (bagian frontend)

**File yang dibuat:**
```
contracts/AegisoeRegistry.sol
contracts/deploy.ts
contracts/test/AegisoeRegistry.test.ts
frontend/src/pages/Dashboard.tsx
frontend/src/pages/IncidentLog.tsx
frontend/src/pages/ProofVerifier.tsx
frontend/src/hooks/useContractEvents.ts
frontend/src/constants/index.ts  ← ABI + contract address
```

---

# E. FRONTEND SPEC MINIMAL

## E.1 ProofVerifier (PRIORITAS UTAMA)

```tsx
// Komponen utama untuk demo
function ProofVerifier() {
  const [secretId, setSecretId] = useState("");
  const { data: incidents } = useReadContract({
    address: CONTRACT_ADDRESS,
    abi: ABI,
    functionName: "getIncidentHistory",
    args: [secretId as `0x${string}`],
  });
  const { data: rotations } = useReadContract({
    address: CONTRACT_ADDRESS,
    abi: ABI,
    functionName: "getRotationHistory",
    args: [secretId as `0x${string}`],
  });

  return (
    <div>
      <input
        placeholder="Enter secretId (bytes32)"
        onChange={(e) => setSecretId(e.target.value)}
      />
      {/* Render incidents table */}
      {/* Render rotations table */}
      {/* Link ke Etherscan untuk setiap tx */}
    </div>
  );
}
```

## E.2 Data yang Ditampilkan

**Incident Table:**
| Field | Source |
|---|---|
| Timestamp | `record.timestamp` |
| Risk Level | `record.riskLevel` |
| Repository | `record.repoName` |
| Status | `record.rotated ? "Rotated" : "Pending"` |
| Incident Commitment | `record.incidentCommitment` |

**Rotation Table:**
| Field | Source |
|---|---|
| Timestamp | `record.timestamp` |
| Old Commitment | `record.oldCommitment` |
| New Commitment | `record.newCommitment` |
| Etherscan Link | `https://sepolia.etherscan.io/...` |

---

# F. STRATEGI JIKA WAKTU MEPET

## Skenario: H-6 jam, belum semua selesai

**Prioritas absolut (WAJIB ada):**
1. CRE simulate video → record apapun yang sudah jalan
2. SecretRotated event di Sepolia → paling tidak 1 tx
3. ProofVerifier bisa query on-chain → live di Vercel

**Yang bisa dimock:**
- Backend webhook → ganti dengan manual trigger script
- Vault → ganti dengan mock response di CRE compute step
- LLM classify → ganti dengan hardcoded "CRITICAL"

**Script manual trigger (jika backend belum siap):**
```typescript
// simulate_trigger.ts — jalankan langsung
const payload = {
  secretId: "0x" + "abc123".padStart(64, "0"),
  repo: "payment-backend",
  commitSha: "abc123def456",
  secretType: "openai",
  vaultUrl: "http://localhost:8200"
};

fetch(process.env.CRE_TRIGGER_URL, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(payload)
});
```

## Skenario: CRE simulate tidak bisa jalan

Jika CRE CLI bermasalah, **jangan panik**. Opsi:
1. Record attempt simulate + error + troubleshoot → tunjukkan effort
2. Gunakan mock CRE output, fokus ke demo frontend + smart contract
3. Explain di video: "Live CRE deployment in progress, here's the workflow spec and simulation steps"

Juri lebih menghargai **proyek yang jujur dan punya workflow spec yang solid** daripada proyek yang crash saat demo karena dipaksakan.

---

# G. SUBMISSION CHECKLIST FINAL

## Mandatory (tanpa ini tidak bisa submit)
```
□ Public GitHub repo
□ README dengan link ke semua file Chainlink
□ Video 3–5 menit, public, tunjukkan CRE execution
□ cre/workflow.yaml ada di repo
```

## Strongly Recommended
```
□ Smart contract verified di Etherscan Sepolia
□ IncidentRecorded event visible di Etherscan
□ SecretRotated event visible di Etherscan
□ Frontend deployed di Vercel
□ ProofVerifier live dan bisa query
```

## Differentiator (yang bikin menang)
```
□ LLM risk classification via Confidential HTTP (Step 3 workflow)
□ CRE live deployment (bukan hanya simulate)
□ Both events dalam satu flow
□ Demo mulus tanpa error
□ README sangat jelas dengan architecture diagram
```

---

# H. ESTIMASI SKOR JURI

Jika semua mandatory + recommended terpenuhi dan demo mulus:

| Kriteria | Score |
|---|---|
| Innovation | 9.0 |
| Chainlink Usage (CRE + Confidential HTTP) | 9.0 |
| Technical Depth | 8.5 |
| Demo Quality | 9.5 |
| Privacy Model Correctness | 9.0 |
| **Estimasi Overall** | **~9.0 / 10** |

**Range ini adalah range pemenang hackathon.**

---

*AEGISOE Blueprint v5.0 — Chainlink Hackathon 2026*
*Gabungan terbaik: feasibility 2 hari + maximum impact ke juri*
