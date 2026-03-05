import { keccak256, toUtf8Bytes, hexlify } from "ethers";

// ── Risk Level Enum (harus match dengan AegisoeRegistry.sol) ─────
export enum RiskLevel {
  NONE = 0,
  MEDIUM = 1,
  HIGH = 2,
  CRITICAL = 3,
}

// Mapping string → uint8 enum
const RISK_MAP: Record<string, RiskLevel> = {
  critical: RiskLevel.CRITICAL,
  high: RiskLevel.HIGH,
  medium: RiskLevel.MEDIUM,
};

export function toRiskLevel(risk: string): RiskLevel {
  return RISK_MAP[risk.toLowerCase()] ?? RiskLevel.NONE;
}

// ── secretId: keccak256 (harus sama dengan CRE Step 8 & SC) ─────
export function encodeSecretId(secretType: string, repo: string): string {
  return keccak256(toUtf8Bytes(`${secretType}_${repo}`));
}

// ── repoName → bytes32 (right-padded UTF-8, max 32 chars) ───────
export function encodeRepoName(repo: string): string {
  const repoBytes = toUtf8Bytes(repo.slice(0, 32));
  const padded = new Uint8Array(32);
  padded.set(repoBytes);
  return hexlify(padded);
}

// ── AegisoeRegistry ABI (minimal — hanya yang dipakai frontend) ──
export const AEGISOE_ABI = [
  "event IncidentRecorded(bytes32 indexed secretId, bytes32 incidentCommitment, uint8 riskLevel, bytes32 repoName, uint256 timestamp)",
  "event SecretRotated(bytes32 indexed secretId, bytes32 oldCommitment, bytes32 newCommitment, uint256 timestamp)",
  "function recordIncident(bytes32 secretId, bytes32 incidentCommitment, uint8 riskLevel, bytes32 repoName) external",
  "function recordRotation(bytes32 secretId, bytes32 oldCommitment, bytes32 newCommitment) external",
  "function getIncidentHistory(bytes32 secretId) external view returns (tuple(bytes32 incidentCommitment, uint8 riskLevel, bytes32 repoName, bool rotated, uint256 timestamp)[])",
  "function getRotationHistory(bytes32 secretId) external view returns (tuple(bytes32 oldCommitment, bytes32 newCommitment, uint256 timestamp)[])",
] as const;
