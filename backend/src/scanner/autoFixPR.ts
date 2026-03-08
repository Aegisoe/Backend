/**
 * Auto-Fix PR — Create a GitHub Pull Request that removes leaked secrets
 *
 * Flow:
 *   1. Create branch: aegisoe/fix-leaked-secrets-{timestamp}
 *   2. For each file with findings:
 *      - .env files → replace values with ***REVOKED_BY_AEGISOE***
 *      - code files → replace leaked values with ***REVOKED_BY_AEGISOE***
 *   3. Add/update .gitignore with .env patterns
 *   4. Create PR with detailed description
 *
 * Requires: GITHUB_API_TOKEN with `repo` scope
 */

import { Finding } from "./repoScanner";

// ── Types ────────────────────────────────────────────────────────

export interface AutoFixResult {
  success: boolean;
  prUrl?: string;
  prNumber?: number;
  branch?: string;
  filesFixed: number;
  gitignoreUpdated: boolean;
  error?: string;
}

interface FileToFix {
  path: string;
  sha: string; // current file SHA (required by GitHub Contents API)
  originalContent: string;
  fixedContent: string;
}

// ── GitHub API Helpers ───────────────────────────────────────────

function githubHeaders(token: string): Record<string, string> {
  return {
    Accept: "application/vnd.github.v3+json",
    Authorization: `Bearer ${token}`,
    "User-Agent": "AEGISOE-AutoFix/1.0",
  };
}

async function githubApi(
  method: string,
  url: string,
  token: string,
  body?: any
): Promise<any> {
  const response = await fetch(url, {
    method,
    headers: {
      ...githubHeaders(token),
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      `GitHub API ${response.status}: ${data.message || JSON.stringify(data)}`
    );
  }

  return data;
}

// ── Sensitive file detection ─────────────────────────────────────
// Files yang seharusnya TIDAK ada di repo sama sekali

const SENSITIVE_FILE_PATTERNS = [
  /^\.env$/,
  /^\.env\..+$/,         // .env.local, .env.production, etc.
  /\.pem$/,
  /\.key$/,
  /\.p12$/,
  /\.pfx$/,
  /\.jks$/,              // Java keystore
  /id_rsa$/,
  /id_ed25519$/,
  /credentials\.json$/,
  /service[-_]?account.*\.json$/,
  /firebase.*\.json$/,
  /\.htpasswd$/,
  /\.pgpass$/,
  /\.netrc$/,
  /\.docker\/config\.json$/,
];

export function isSensitiveFile(filePath: string): boolean {
  const fileName = filePath.split("/").pop() || "";
  return SENSITIVE_FILE_PATTERNS.some((p) => p.test(fileName) || p.test(filePath));
}

// .gitignore entries for sensitive files
const GITIGNORE_ENTRIES = [
  "# ── Secrets & sensitive files (added by AEGISOE) ──",
  ".env",
  ".env.*",
  ".env.local",
  ".env.production",
  ".env.staging",
  "*.pem",
  "*.key",
  "*.p12",
  "*.pfx",
  "*.jks",
  "id_rsa",
  "id_ed25519",
  "credentials.json",
  "service-account*.json",
  ".htpasswd",
  ".pgpass",
  ".netrc",
];

// ── Content Fixers ───────────────────────────────────────────────

function fixEnvFile(content: string, findings: Finding[]): string {
  const lines = content.split("\n");

  for (const finding of findings) {
    // Replace the leaked value in the matching line
    const lineIdx = finding.line - 1;
    if (lineIdx >= 0 && lineIdx < lines.length) {
      // Match KEY=value pattern and replace value
      lines[lineIdx] = lines[lineIdx].replace(
        /([=:]\s*['"]?)([^\s'"#]+)(['"]?\s*)/,
        `$1***REVOKED_BY_AEGISOE***$3`
      );
    }
  }

  return lines.join("\n");
}

function fixCodeFile(content: string, findings: Finding[]): string {
  let fixed = content;

  for (const finding of findings) {
    // Replace the actual leaked value with revoked placeholder
    // Use the matchedValue to do exact replacement
    const escaped = finding.maskedValue; // We don't have the raw value here
    // But we stored matchedValue in Finding — however we masked it in the API response
    // So we need to pass raw values separately for fixing
    // For now, replace line by line
    const lines = fixed.split("\n");
    const lineIdx = finding.line - 1;
    if (lineIdx >= 0 && lineIdx < lines.length) {
      // Replace any high-entropy string or known pattern on that line
      lines[lineIdx] = replaceSecretInLine(lines[lineIdx], finding.secretType);
    }
    fixed = lines.join("\n");
  }

  return fixed;
}

function replaceSecretInLine(line: string, secretType: string): string {
  const replacements: Record<string, { pattern: RegExp; replacement: string }> = {
    openai:       { pattern: /sk-[a-zA-Z0-9_\-]{20,}/g, replacement: '"***REVOKED_BY_AEGISOE***"' },
    aws:          { pattern: /AKIA[0-9A-Z]{16}/g, replacement: "***REVOKED_BY_AEGISOE***" },
    github:       { pattern: /gh[ps]_[a-zA-Z0-9]{36,}/g, replacement: "***REVOKED_BY_AEGISOE***" },
    gitlab:       { pattern: /glpat-[a-zA-Z0-9_\-]{20,}/g, replacement: "***REVOKED_BY_AEGISOE***" },
    stripe:       { pattern: /sk_(?:live|test)_[a-zA-Z0-9]{24,}/g, replacement: "***REVOKED_BY_AEGISOE***" },
    stripe_test:  { pattern: /sk_test_[a-zA-Z0-9]{24,}/g, replacement: "***REVOKED_BY_AEGISOE***" },
    google_api:   { pattern: /AIza[a-zA-Z0-9_\-]{35}/g, replacement: "***REVOKED_BY_AEGISOE***" },
    sendgrid:     { pattern: /SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g, replacement: "***REVOKED_BY_AEGISOE***" },
    slack_webhook:{ pattern: /https:\/\/hooks\.slack\.com\/services\/[^\s'"]+/g, replacement: "***REVOKED_BY_AEGISOE***" },
    slack_token:  { pattern: /xox[bpras]-[a-zA-Z0-9\-]+/g, replacement: "***REVOKED_BY_AEGISOE***" },
    jwt:          { pattern: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, replacement: "***REVOKED_BY_AEGISOE***" },
    private_key:  { pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, replacement: "***PRIVATE_KEY_REVOKED_BY_AEGISOE***" },
    database_url: { pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s'"]+/g, replacement: "***DATABASE_URL_REVOKED_BY_AEGISOE***" },
    env_secret:   { pattern: /([=:]\s*['"]?)([^\s'"#]{8,})(['"]?\s*$)/g, replacement: "$1***REVOKED_BY_AEGISOE***$3" },
  };

  const rule = replacements[secretType];
  if (rule) {
    return line.replace(rule.pattern, rule.replacement);
  }

  // Generic fallback: replace high-entropy strings on the line
  return line.replace(
    /(['"])[a-zA-Z0-9_\-]{32,}(['"])/g,
    '$1***REVOKED_BY_AEGISOE***$2'
  );
}

// ── Main Auto-Fix ────────────────────────────────────────────────

export async function createAutoFixPR(
  owner: string,
  repo: string,
  baseBranch: string,
  findings: Finding[],
  sensitiveFiles: string[],
  token: string
): Promise<AutoFixResult> {
  const apiBase = `https://api.github.com/repos/${owner}/${repo}`;
  const timestamp = Date.now();
  const fixBranch = `aegisoe/fix-leaked-secrets-${timestamp}`;

  console.log(`\n🔧 AUTO-FIX PR — Creating fix for ${owner}/${repo}`);
  console.log(`   Branch    : ${fixBranch}`);
  console.log(`   Findings  : ${findings.length} secrets in code`);
  console.log(`   Sensitive : ${sensitiveFiles.length} files to .gitignore`);

  try {
    // 1. Get base branch SHA
    const refData = await githubApi(
      "GET",
      `${apiBase}/git/ref/heads/${baseBranch}`,
      token
    );
    const baseSha = refData.object.sha;
    console.log(`   Base SHA  : ${baseSha.slice(0, 8)}`);

    // 2. Create fix branch
    await githubApi("POST", `${apiBase}/git/refs`, token, {
      ref: `refs/heads/${fixBranch}`,
      sha: baseSha,
    });
    console.log(`   ✅ Branch created: ${fixBranch}`);

    // 3. Group findings by file
    const findingsByFile = new Map<string, Finding[]>();
    for (const f of findings) {
      const existing = findingsByFile.get(f.file) || [];
      existing.push(f);
      findingsByFile.set(f.file, existing);
    }

    // 4. Fix each file
    let filesFixed = 0;
    for (const [filePath, fileFindings] of findingsByFile) {
      try {
        // Fetch current file content + SHA
        const fileData = await githubApi(
          "GET",
          `${apiBase}/contents/${encodeURIComponent(filePath)}?ref=${fixBranch}`,
          token
        );

        const content = Buffer.from(fileData.content, "base64").toString("utf-8");
        const isEnvFile = filePath.includes(".env") || isSensitiveFile(filePath);

        const fixedContent = isEnvFile
          ? fixEnvFile(content, fileFindings)
          : fixCodeFile(content, fileFindings);

        if (fixedContent === content) continue; // no change

        // Update file on fix branch
        await githubApi(
          "PUT",
          `${apiBase}/contents/${encodeURIComponent(filePath)}`,
          token,
          {
            message: `fix: revoke leaked secrets in ${filePath} [AEGISOE]`,
            content: Buffer.from(fixedContent).toString("base64"),
            sha: fileData.sha,
            branch: fixBranch,
          }
        );

        filesFixed++;
        console.log(`   ✅ Fixed: ${filePath} (${fileFindings.length} secrets)`);
      } catch (err: any) {
        console.error(`   ❌ Failed to fix ${filePath}: ${err.message}`);
      }
    }

    // 5. Update .gitignore
    let gitignoreUpdated = false;
    if (sensitiveFiles.length > 0) {
      try {
        // Try to get existing .gitignore
        let existingContent = "";
        let existingSha: string | undefined;

        try {
          const gitignoreData = await githubApi(
            "GET",
            `${apiBase}/contents/.gitignore?ref=${fixBranch}`,
            token
          );
          existingContent = Buffer.from(gitignoreData.content, "base64").toString("utf-8");
          existingSha = gitignoreData.sha;
        } catch {
          // .gitignore doesn't exist — will create new
        }

        // Add missing entries
        const newEntries = GITIGNORE_ENTRIES.filter(
          (entry) => !entry.startsWith("#") && !existingContent.includes(entry)
        );

        if (newEntries.length > 0) {
          const updatedContent = existingContent.trimEnd() +
            "\n\n" + GITIGNORE_ENTRIES.join("\n") + "\n";

          const body: any = {
            message: "fix: add sensitive file patterns to .gitignore [AEGISOE]",
            content: Buffer.from(updatedContent).toString("base64"),
            branch: fixBranch,
          };
          if (existingSha) body.sha = existingSha;

          await githubApi("PUT", `${apiBase}/contents/.gitignore`, token, body);
          gitignoreUpdated = true;
          console.log(`   ✅ .gitignore updated with ${newEntries.length} entries`);
        }
      } catch (err: any) {
        console.error(`   ❌ Failed to update .gitignore: ${err.message}`);
      }
    }

    // 6. Create Pull Request
    const prBody = buildPRDescription(findings, sensitiveFiles, gitignoreUpdated);

    const pr = await githubApi("POST", `${apiBase}/pulls`, token, {
      title: `[AEGISOE] Fix ${findings.length} leaked secret(s) detected`,
      head: fixBranch,
      base: baseBranch,
      body: prBody,
    });

    console.log(`\n✅ PR created: ${pr.html_url}`);

    return {
      success: true,
      prUrl: pr.html_url,
      prNumber: pr.number,
      branch: fixBranch,
      filesFixed,
      gitignoreUpdated,
    };
  } catch (err: any) {
    console.error(`❌ Auto-fix PR failed: ${err.message}`);
    return {
      success: false,
      filesFixed: 0,
      gitignoreUpdated: false,
      error: err.message,
    };
  }
}

// ── PR Description Builder ───────────────────────────────────────

function buildPRDescription(
  findings: Finding[],
  sensitiveFiles: string[],
  gitignoreUpdated: boolean
): string {
  const critical = findings.filter((f) => f.riskLevel === "CRITICAL").length;
  const high = findings.filter((f) => f.riskLevel === "HIGH").length;
  const medium = findings.filter((f) => f.riskLevel === "MEDIUM").length;

  const uniqueFiles = [...new Set(findings.map((f) => f.file))];

  let body = `## AEGISOE — Automated Secret Leak Fix\n\n`;
  body += `AEGISOE detected **${findings.length} leaked secret(s)** in this repository and automatically created this PR to remediate them.\n\n`;

  body += `### Summary\n`;
  body += `| Risk Level | Count |\n|---|---|\n`;
  if (critical > 0) body += `| CRITICAL | ${critical} |\n`;
  if (high > 0) body += `| HIGH | ${high} |\n`;
  if (medium > 0) body += `| MEDIUM | ${medium} |\n`;
  body += `| **Total** | **${findings.length}** |\n\n`;

  body += `### Files Modified\n`;
  for (const file of uniqueFiles) {
    const fileFindings = findings.filter((f) => f.file === file);
    body += `- \`${file}\` — ${fileFindings.length} secret(s) revoked\n`;
  }
  body += `\n`;

  if (sensitiveFiles.length > 0) {
    body += `### Sensitive Files Detected\n`;
    body += `These files should **not be in the repository**:\n`;
    for (const f of sensitiveFiles) {
      body += `- \`${f}\`\n`;
    }
    body += `\n`;
  }

  if (gitignoreUpdated) {
    body += `### .gitignore Updated\n`;
    body += `Added patterns to prevent future leaks of sensitive files.\n\n`;
  }

  body += `### Findings Detail\n`;
  body += `| File | Line | Type | Risk | Masked Value |\n|---|---|---|---|---|\n`;
  for (const f of findings) {
    const risk = f.riskLevel === "CRITICAL" ? "**CRITICAL**" : f.riskLevel;
    body += `| \`${f.file}\` | L${f.line} | ${f.secretType} | ${risk} | \`${f.maskedValue}\` |\n`;
  }
  body += `\n`;

  body += `### Action Required\n`;
  body += `1. **Review** this PR carefully before merging\n`;
  body += `2. **Rotate** all affected secrets immediately — revoking in code does NOT invalidate the key\n`;
  body += `3. **Merge** this PR to remove secrets from the default branch\n`;
  body += `4. Consider [removing secrets from git history](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)\n\n`;

  body += `---\n`;
  body += `*Automated by [AEGISOE Security Engine](https://github.com/Aegisoe) — 3-layer detection (Regex + Entropy + LLM)*\n`;

  return body;
}
