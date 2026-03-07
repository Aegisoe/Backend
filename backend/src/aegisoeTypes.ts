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
  // SC reverts on NONE (0) — fallback ke MEDIUM (1) bukan NONE
  return RISK_MAP[risk.toLowerCase()] ?? RiskLevel.MEDIUM;
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

// ── Contract Addresses (Sepolia) ─────────────────────────────────
export const CONTRACT_ADDRESS = "0xf497C0B1D82d6fc1deaFe63a2DB7dBe81d87Da71";
export const CRE_OPERATOR_ADDRESS = "0x6b75074B52d17A1FD101ED984605e3EF2EAB5e57";

// ── AegisoeRegistry ABI (match deployed contract on Sepolia) ─────
export const AEGISOE_ABI = [
  // Events
  "event IncidentRecorded(bytes32 indexed secretId, address indexed operator, bytes32 incidentCommitment, uint8 riskLevel, bytes32 repoName, uint48 timestamp)",
  "event SecretRotated(bytes32 indexed secretId, address indexed operator, bytes32 oldCommitment, bytes32 newCommitment, uint48 timestamp)",
  "event OperatorAuthorized(address indexed operator)",
  "event OperatorRevoked(address indexed operator)",
  // Write
  "function recordIncident(bytes32 secretId, bytes32 incidentCommitment, uint8 riskLevel, bytes32 repoName) external",
  "function recordRotation(bytes32 secretId, bytes32 oldCommitment, bytes32 newCommitment) external",
  // Read (paginated)
  "function getIncidentHistory(bytes32 secretId, uint256 offset, uint256 limit) external view returns (tuple(address operator, bytes32 incidentCommitment, bytes32 repoName, uint48 timestamp, uint8 riskLevel, bool rotated)[])",
  "function getRotationHistory(bytes32 secretId, uint256 offset, uint256 limit) external view returns (tuple(address operator, bytes32 oldCommitment, bytes32 newCommitment, uint48 timestamp)[])",
  "function getIncidentCount(bytes32 secretId) external view returns (uint256)",
  "function getRotationCount(bytes32 secretId) external view returns (uint256)",
  "function isLatestIncidentRotated(bytes32 secretId) external view returns (bool)",
  "function authorizedOperators(address) external view returns (bool)",
] as const;
