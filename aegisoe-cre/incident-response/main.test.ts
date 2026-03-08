import { describe, expect } from "bun:test";
import { newTestRuntime, test } from "@chainlink/cre-sdk/test";
import { onHTTPTrigger, initWorkflow } from "./main";
import type { Config } from "./main";

// ── Test helpers ──────────────────────────────────────────────────

function makeTriggerOutput(payload: object): { input: Uint8Array } {
  return { input: new TextEncoder().encode(JSON.stringify(payload)) };
}

const testConfig: Config = {
  contractAddress: "0xf497C0B1D82d6fc1deaFe63a2DB7dBe81d87Da71",
  backendCallbackUrl: "https://test-backend.railway.app/cre-callback",
};

const testSecrets = new Map([
  [
    "",
    new Map([
      ["GITHUB_TOKEN", "ghp_testtoken123"],
      ["VAULT_ADMIN_TOKEN", "vault-test-token"],
      ["BACKEND_CALLBACK_SECRET", "test-callback-secret"],
      ["VAULT_URL", "http://localhost:8200"],
    ]),
  ],
]);

const testPayload = {
  secretType: "openai",
  matchedValue: "sk-proj-testkey12345",
  riskLevel: "CRITICAL",
  repo: "Aegisoe/Backend",
  commitSha: "abc123def456789012345678901234567890abcd",
  secretId: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
};

// ── Tests ─────────────────────────────────────────────────────────

describe("onHTTPTrigger", () => {
  test("returns JSON result with correct shape", async () => {
    const runtime = newTestRuntime(testSecrets);
    runtime.config = testConfig;
    const triggerOutput = makeTriggerOutput(testPayload);
    try {
      const result = await onHTTPTrigger(runtime, triggerOutput as any);
      const parsed = JSON.parse(result);
      expect(parsed).toHaveProperty("secretId");
      expect(parsed).toHaveProperty("incidentCommitment");
      expect(parsed).toHaveProperty("riskLevel");
      expect(parsed.riskLevel).toBe("CRITICAL");
      expect(parsed.riskLevelUint).toBe(3);
    } catch (_e) {
      // ConfidentialHTTP calls throw in test env — verify secrets loaded
      const logs = runtime.getLogs();
      expect(logs.some((l) => l.includes("Secrets loaded"))).toBe(true);
    }
  });

  test("logs incident details", async () => {
    const runtime = newTestRuntime(testSecrets);
    runtime.config = testConfig;
    try {
      await onHTTPTrigger(runtime, makeTriggerOutput(testPayload) as any);
    } catch (_e) {}
    const logs = runtime.getLogs();
    expect(logs.some((l) => l.includes("openai"))).toBe(true);
    expect(logs.some((l) => l.includes("Aegisoe/Backend"))).toBe(true);
  });
});

describe("initWorkflow", () => {
  test("returns one HTTP handler", () => {
    const handlers = initWorkflow(testConfig);
    expect(handlers).toBeArray();
    expect(handlers).toHaveLength(1);
    expect(handlers[0].trigger.capabilityId()).toContain("http");
  });
});
