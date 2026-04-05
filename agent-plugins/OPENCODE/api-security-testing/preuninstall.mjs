#!/usr/bin/env node

/**
 * preuninstall.mjs - API Security Testing Plugin Cleanup
 * 
 * Removes:
 * 1. agents from ~/.config/opencode/agents/
 * 2. SKILL.md and references from ~/.config/opencode/skills/api-security-testing/
 */

import { unlinkSync, existsSync, readdirSync, rmdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = join(__filename, "..");

function getOpencodeBaseDir() {
  const home = process.env.HOME || process.env.USERPROFILE || "/root";
  return join(home, ".config", "opencode");
}

const AGENTS_TO_REMOVE = [
  "api-cyber-supervisor.md",
  "api-probing-miner.md",
  "api-resource-specialist.md",
  "api-vuln-verifier.md",
];

function main() {
  const agentsTargetDir = join(getOpencodeBaseDir(), "agents");
  const skillTargetDir = join(getOpencodeBaseDir(), "skills", "api-security-testing");
  
  console.log("[api-security-testing] Cleaning up...");
  console.log(`  Home: ${getOpencodeBaseDir()}`);

  let totalRemoved = 0;
  let totalFailed = 0;

  console.log("\n[1/2] Removing agents...");
  for (const agent of AGENTS_TO_REMOVE) {
    const agentPath = join(agentsTargetDir, agent);
    try {
      if (existsSync(agentPath)) {
        unlinkSync(agentPath);
        console.log(`  ✓ ${agent}`);
        totalRemoved++;
      }
    } catch (err) {
      console.error(`  ✗ ${agent}: ${err.message}`);
      totalFailed++;
    }
  }

  console.log("\n[2/2] Removing skill files...");
  try {
    if (existsSync(skillTargetDir)) {
      rmSync(skillTargetDir, { recursive: true, force: true });
      console.log(`  ✓ ${skillTargetDir}`);
      totalRemoved++;
    }
  } catch (err) {
    console.error(`  ✗ ${skillTargetDir}: ${err.message}`);
    totalFailed++;
  }

  console.log(`\n========================================`);
  if (totalFailed === 0) {
    console.log(`✓ Removed ${totalRemoved} item(s)`);
    console.log(`\nThanks for using api-security-testing!`);
  } else {
    console.log(`⚠ Removed ${totalRemoved}, failed ${totalFailed}`);
  }
}

main();
