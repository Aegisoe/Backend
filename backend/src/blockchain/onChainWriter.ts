/**
 * On-Chain Writer — AegisoeRegistry (Sepolia)
 *
 * Submit incident + rotation records ke smart contract.
 * Dipanggil setelah CRE callback (atau langsung di mock mode).
 *
 * Env vars yang dibutuhkan:
 *   OPERATOR_PRIVATE_KEY  — private key dari CRE_OPERATOR_ADDRESS
 *   SEPOLIA_RPC_URL       — (opsional) Sepolia RPC, default pakai public node
 */

import { ethers } from "ethers";
import {
  AEGISOE_ABI,
  CONTRACT_ADDRESS,
  encodeRepoName,
} from "../aegisoeTypes";

// ── Provider + Signer ────────────────────────────────────────────

function getSigner(): ethers.Wallet {
  const pk = process.env.OPERATOR_PRIVATE_KEY;
  if (!pk) throw new Error("OPERATOR_PRIVATE_KEY not set in environment");

  const rpcUrl =
    process.env.SEPOLIA_RPC_URL ||
    "https://ethereum-sepolia-rpc.publicnode.com";

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  return new ethers.Wallet(pk, provider);
}

function getContract(signer: ethers.Wallet): ethers.Contract {
  return new ethers.Contract(CONTRACT_ADDRESS, AEGISOE_ABI, signer);
}

// ── recordIncident ───────────────────────────────────────────────

export interface RecordIncidentParams {
  secretId: string;            // bytes32 hex (keccak256)
  incidentCommitment: string;  // bytes32 hex (SHA-256 dari TEE atau mock)
  riskLevel: number;           // 1=MEDIUM, 2=HIGH, 3=CRITICAL (jangan 0!)
  repo: string;                // "owner/repo-name"
}

export async function recordIncidentOnChain(
  params: RecordIncidentParams
): Promise<string> {
  const signer = getSigner();
  const contract = getContract(signer);

  const repoBytes32 = encodeRepoName(params.repo);

  console.log(`\n⛓️  Submitting recordIncident to Sepolia...`);
  console.log(`   SecretId   : ${params.secretId}`);
  console.log(`   Commitment : ${params.incidentCommitment.slice(0, 18)}...`);
  console.log(`   RiskLevel  : ${params.riskLevel}`);
  console.log(`   Repo       : ${params.repo}`);

  const tx = await contract.recordIncident(
    params.secretId,
    params.incidentCommitment,
    params.riskLevel,
    repoBytes32
  );

  console.log(`   TX sent    : ${tx.hash}`);
  await tx.wait();
  console.log(`   ✅ Confirmed on Sepolia: ${tx.hash}`);
  console.log(`   🔗 https://sepolia.etherscan.io/tx/${tx.hash}`);

  return tx.hash as string;
}

// ── recordRotation ───────────────────────────────────────────────

export interface RecordRotationParams {
  secretId: string;
  oldCommitment: string; // incidentCommitment (sebelum rotasi)
  newCommitment: string; // commitment setelah rotasi (dari Vault)
}

export async function recordRotationOnChain(
  params: RecordRotationParams
): Promise<string> {
  const signer = getSigner();
  const contract = getContract(signer);

  console.log(`\n⛓️  Submitting recordRotation to Sepolia...`);
  console.log(`   SecretId   : ${params.secretId}`);
  console.log(`   OldCommit  : ${params.oldCommitment.slice(0, 18)}...`);
  console.log(`   NewCommit  : ${params.newCommitment.slice(0, 18)}...`);

  const tx = await contract.recordRotation(
    params.secretId,
    params.oldCommitment,
    params.newCommitment
  );

  console.log(`   TX sent    : ${tx.hash}`);
  await tx.wait();
  console.log(`   ✅ Confirmed on Sepolia: ${tx.hash}`);
  console.log(`   🔗 https://sepolia.etherscan.io/tx/${tx.hash}`);

  return tx.hash as string;
}

// ── Mock commitments (untuk mock mode tanpa real CRE) ────────────
// Menghasilkan bytes32 deterministik dari secretId + commitSha

import { keccak256, toUtf8Bytes } from "ethers";

export function generateMockCommitment(
  secretId: string,
  commitSha: string,
  suffix: string = "incident"
): string {
  return keccak256(toUtf8Bytes(`${secretId}_${commitSha}_${suffix}`));
}
