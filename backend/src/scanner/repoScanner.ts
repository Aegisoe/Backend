/**
 * GitHub Repository Scanner
 *
 * Scan seluruh repo GitHub untuk mendeteksi leaked secrets.
 * Menggunakan GitHub API untuk fetch repo tree + file contents,
 * lalu jalankan 3-layer detection: Regex → Entropy → LLM.
 *
 * Flow:
 *   1. Parse GitHub URL → owner/repo
 *   2. GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1
 *   3. Filter file yang berpotensi mengandung secret
 *   4. Fetch content per file via Contents API
 *   5. scanTextForAllSecrets() per file
 *   6. classifyWithLLM() per finding (batch)
 *   7. Return structured results
 */

import { scanTextForAllSecrets, SecretMatch } from "../detection/regexScanner";
import { classifyWithLLM, LLMClassifyResult } from "../detection/llmClassifier";
import { isSensitiveFile, createAutoFixPR, AutoFixResult } from "./autoFixPR";

// ── Types ────────────────────────────────────────────────────────

export interface RepoScanOptions {
  repoUrl: string;
  branch?: string;
  mode?: "simulate" | "onchain";
  autoFix?: boolean; // create PR to fix leaked secrets
  token?: string; // GitHub API token (optional, higher rate limit)
  maxFiles?: number; // limit files to scan (default 50)
}

export interface Finding {
  file: string;
  line: number;
  secretType: string;
  maskedValue: string;
  entropy: number;
  riskLevel: string;
  llmVerified: boolean;
  llmReasoning: string;
}

export interface RepoScanResult {
  status: "completed" | "partial" | "error";
  repo: string;
  branch: string;
  scanDuration: number;
  totalFilesScanned: number;
  totalFilesInRepo: number;
  findings: Finding[];
  sensitiveFiles: string[]; // files that should NOT be in repo (.env, .pem, etc.)
  summary: {
    critical: number;
    high: number;
    medium: number;
    total: number;
    sensitiveFilesCount: number;
  };
  autoFix?: AutoFixResult;
  error?: string;
}

interface TreeEntry {
  path: string;
  type: "blob" | "tree";
  size?: number;
  sha: string;
  url: string;
}

// ── Config ───────────────────────────────────────────────────────

// File extensions yang berpotensi mengandung secret
const SCANNABLE_EXTENSIONS = new Set([
  ".env",
  ".js",
  ".ts",
  ".jsx",
  ".tsx",
  ".py",
  ".rb",
  ".go",
  ".java",
  ".json",
  ".yaml",
  ".yml",
  ".toml",
  ".ini",
  ".cfg",
  ".conf",
  ".sh",
  ".bash",
  ".zsh",
  ".properties",
  ".xml",
  ".tf",        // Terraform
  ".tfvars",
  ".php",
  ".rs",        // Rust
  ".cs",        // C#
  ".swift",
  ".kt",        // Kotlin
]);

// File names yang PASTI harus di-scan (tanpa lihat extension)
const HIGH_PRIORITY_FILES = new Set([
  ".env",
  ".env.local",
  ".env.production",
  ".env.development",
  ".env.staging",
  ".env.test",
  "Dockerfile",
  "docker-compose.yml",
  "docker-compose.yaml",
  ".npmrc",
  ".pypirc",
  "credentials",
  "secrets.json",
  "secrets.yaml",
  "secrets.yml",
]);

// Directories yang di-skip (tidak mungkin ada secret, membuang waktu)
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "vendor",
  "dist",
  "build",
  ".next",
  "__pycache__",
  ".cache",
  "coverage",
  ".vscode",
  ".idea",
  "assets",
  "images",
  "fonts",
  "public/images",
]);

// Lock files — skip (besar, tidak ada secret)
const SKIP_FILES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lockb",
  "Cargo.lock",
  "Gemfile.lock",
  "poetry.lock",
  "composer.lock",
  "go.sum",
]);

const MAX_FILE_SIZE = 100_000; // 100KB — skip files larger than this

// ── GitHub URL Parser ────────────────────────────────────────────

export function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  // Support formats:
  //   https://github.com/owner/repo
  //   https://github.com/owner/repo.git
  //   github.com/owner/repo
  //   owner/repo

  let cleaned = url.trim().replace(/\.git$/, "").replace(/\/$/, "");

  // Full URL
  const urlMatch = cleaned.match(
    /(?:https?:\/\/)?github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)/
  );
  if (urlMatch) {
    return { owner: urlMatch[1], repo: urlMatch[2] };
  }

  // Short format: owner/repo
  const shortMatch = cleaned.match(/^([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)$/);
  if (shortMatch) {
    return { owner: shortMatch[1], repo: shortMatch[2] };
  }

  return null;
}

// ── GitHub API Helpers ───────────────────────────────────────────

function githubHeaders(token?: string): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "AEGISOE-Scanner/1.0",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

async function fetchRepoTree(
  owner: string,
  repo: string,
  branch: string,
  token?: string
): Promise<TreeEntry[]> {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`;
  console.log(`   📂 Fetching repo tree: ${owner}/${repo}@${branch}`);

  const response = await fetch(url, { headers: githubHeaders(token) });

  if (!response.ok) {
    const errText = await response.text();
    if (response.status === 404) {
      throw new Error(`Repository not found: ${owner}/${repo} (branch: ${branch})`);
    }
    if (response.status === 403) {
      throw new Error(`GitHub API rate limited. Set GITHUB_API_TOKEN for higher limits.`);
    }
    throw new Error(`GitHub API error ${response.status}: ${errText}`);
  }

  const data = (await response.json()) as { tree: TreeEntry[]; truncated: boolean };

  if (data.truncated) {
    console.warn(`   ⚠️  Repo tree truncated (very large repo) — some files may be missed`);
  }

  return data.tree;
}

async function fetchFileContent(
  owner: string,
  repo: string,
  path: string,
  token?: string
): Promise<string | null> {
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;

  const response = await fetch(url, { headers: githubHeaders(token) });

  if (!response.ok) return null;

  const data = (await response.json()) as {
    content?: string;
    encoding?: string;
    size: number;
  };

  if (!data.content || data.encoding !== "base64") return null;

  try {
    return Buffer.from(data.content, "base64").toString("utf-8");
  } catch {
    return null;
  }
}

// ── File Filter ──────────────────────────────────────────────────

function shouldScanFile(entry: TreeEntry): boolean {
  if (entry.type !== "blob") return false;
  if (entry.size && entry.size > MAX_FILE_SIZE) return false;

  const path = entry.path;
  const fileName = path.split("/").pop() || "";

  // Skip known directories
  for (const dir of SKIP_DIRS) {
    if (path.startsWith(dir + "/") || path.includes("/" + dir + "/")) return false;
  }

  // Skip lock files
  if (SKIP_FILES.has(fileName)) return false;

  // High priority files — always scan
  if (HIGH_PRIORITY_FILES.has(fileName)) return true;

  // Check extension
  const ext = getExtension(fileName);
  if (ext && SCANNABLE_EXTENSIONS.has(ext)) return true;

  // .env variants
  if (fileName.startsWith(".env")) return true;

  return false;
}

function getExtension(filename: string): string | null {
  const dot = filename.lastIndexOf(".");
  if (dot === -1 || dot === 0) return null;
  return filename.substring(dot).toLowerCase();
}

// ── Main Scanner ─────────────────────────────────────────────────

export async function scanRepository(options: RepoScanOptions): Promise<RepoScanResult> {
  const startTime = Date.now();
  const maxFiles = options.maxFiles || 50;
  const branch = options.branch || "main";
  const token = options.token || process.env.GITHUB_API_TOKEN;

  // 1. Parse URL
  const parsed = parseGitHubUrl(options.repoUrl);
  if (!parsed) {
    return {
      status: "error",
      repo: options.repoUrl,
      branch,
      scanDuration: Date.now() - startTime,
      totalFilesScanned: 0,
      totalFilesInRepo: 0,
      findings: [],
      sensitiveFiles: [],
      summary: { critical: 0, high: 0, medium: 0, total: 0, sensitiveFilesCount: 0 },
      error: "Invalid GitHub URL. Expected: https://github.com/owner/repo",
    };
  }

  const { owner, repo } = parsed;
  const repoFullName = `${owner}/${repo}`;
  console.log(`\n🔍 REPO SCANNER — Scanning ${repoFullName}@${branch}`);

  try {
    // 2. Fetch repo tree
    const tree = await fetchRepoTree(owner, repo, branch, token);
    const allFiles = tree.filter((e) => e.type === "blob");

    // 2.5. Detect sensitive files that should NOT be in repo
    const sensitiveFiles = allFiles
      .filter((e) => e.type === "blob" && isSensitiveFile(e.path))
      .map((e) => e.path);

    if (sensitiveFiles.length > 0) {
      console.log(`   ⚠️  Sensitive files found: ${sensitiveFiles.length}`);
      for (const f of sensitiveFiles) {
        console.log(`      - ${f}`);
      }
    }

    // 3. Filter scannable files + sort by priority
    const scannableFiles = allFiles
      .filter(shouldScanFile)
      .sort((a, b) => {
        // Prioritize .env files and config files
        const aName = a.path.split("/").pop() || "";
        const bName = b.path.split("/").pop() || "";
        const aPriority = HIGH_PRIORITY_FILES.has(aName) ? 0 : 1;
        const bPriority = HIGH_PRIORITY_FILES.has(bName) ? 0 : 1;
        return aPriority - bPriority;
      })
      .slice(0, maxFiles);

    console.log(`   Total files : ${allFiles.length}`);
    console.log(`   Scannable   : ${scannableFiles.length} (max ${maxFiles})`);

    // 4. Fetch + scan each file
    const findings: Finding[] = [];
    let filesScanned = 0;

    for (const file of scannableFiles) {
      const content = await fetchFileContent(owner, repo, file.path, token);
      if (!content) continue;

      filesScanned++;
      const matches = scanTextForAllSecrets(content);

      if (matches.length > 0) {
        console.log(`   🚨 ${file.path} — ${matches.length} potential secret(s)`);
      }

      // 5. LLM classify each match
      for (const match of matches) {
        const fileContext = extractContext(content, match.line, 3);

        let llmResult: LLMClassifyResult;
        try {
          llmResult = await classifyWithLLM(match.matchedValue, match.secretType, fileContext);
        } catch {
          llmResult = {
            isLeak: true,
            riskLevel: "MEDIUM",
            reasoning: "LLM unavailable — classified by entropy + pattern",
            mode: "fallback",
          };
        }

        // Only include if LLM confirms it's a leak (or fallback)
        if (llmResult.isLeak) {
          findings.push({
            file: file.path,
            line: match.line,
            secretType: match.secretType,
            maskedValue: match.maskedValue,
            entropy: Math.round(match.entropy * 100) / 100,
            riskLevel: llmResult.riskLevel,
            llmVerified: llmResult.mode === "llm",
            llmReasoning: llmResult.reasoning,
          });
        }
      }
    }

    // 6. Build summary
    const summary = {
      critical: findings.filter((f) => f.riskLevel === "CRITICAL").length,
      high: findings.filter((f) => f.riskLevel === "HIGH").length,
      medium: findings.filter((f) => f.riskLevel === "MEDIUM").length,
      total: findings.length,
      sensitiveFilesCount: sensitiveFiles.length,
    };

    const duration = Date.now() - startTime;
    console.log(`\n✅ Scan complete: ${summary.total} secrets found in ${duration}ms`);
    console.log(`   CRITICAL: ${summary.critical} | HIGH: ${summary.high} | MEDIUM: ${summary.medium}`);
    if (sensitiveFiles.length > 0) {
      console.log(`   Sensitive files: ${sensitiveFiles.length} (should not be in repo)`);
    }

    const result: RepoScanResult = {
      status: filesScanned === scannableFiles.length ? "completed" : "partial",
      repo: repoFullName,
      branch,
      scanDuration: duration,
      totalFilesScanned: filesScanned,
      totalFilesInRepo: allFiles.length,
      findings,
      sensitiveFiles,
      summary,
    };

    // 7. Auto-fix: create PR to remove leaked secrets
    if (options.autoFix && token && (findings.length > 0 || sensitiveFiles.length > 0)) {
      console.log(`\n🔧 Auto-fix enabled — creating PR...`);
      result.autoFix = await createAutoFixPR(
        owner,
        repo,
        branch,
        findings,
        sensitiveFiles,
        token
      );
    }

    return result;
  } catch (err: any) {
    console.error(`❌ Repo scan error: ${err.message}`);
    return {
      status: "error",
      repo: repoFullName,
      branch,
      scanDuration: Date.now() - startTime,
      totalFilesScanned: 0,
      totalFilesInRepo: 0,
      findings: [],
      sensitiveFiles: [],
      summary: { critical: 0, high: 0, medium: 0, total: 0, sensitiveFilesCount: 0 },
      error: err.message,
    };
  }
}

// ── Helpers ──────────────────────────────────────────────────────

function extractContext(content: string, lineNum: number, radius: number): string {
  const lines = content.split("\n");
  const start = Math.max(0, lineNum - 1 - radius);
  const end = Math.min(lines.length, lineNum + radius);
  return lines.slice(start, end).join("\n");
}
