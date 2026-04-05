#!/usr/bin/env node

/**
 * postinstall.mjs - API Security Testing Plugin
 * 
 * Installs:
 * 1. Agents to ~/.config/opencode/agents/
 * 2. Skill (SKILL.md) to ~/.config/opencode/skills/api-security-testing/
 * 3. References to ~/.config/opencode/skills/api-security-testing/
 */

import { copyFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function getOpencodeBaseDir() {
  const home = process.env.HOME || process.env.USERPROFILE || "/root";
  return join(home, ".config", "opencode");
}

function main() {
  const packageRoot = __dirname;
  const agentsSourceDir = join(packageRoot, "agents");
  const agentsTargetDir = join(getOpencodeBaseDir(), "agents");
  const skillTargetDir = join(getOpencodeBaseDir(), "skills", "api-security-testing");
  
  console.log("[api-security-testing] Installing...");
  console.log(`  Package root: ${packageRoot}`);
  console.log(`  Target base: ${getOpencodeBaseDir()}`);

  let successCount = 0;
  let totalFiles = 0;

  // 1. Install agents
  console.log("\n[1/3] Installing agents...");
  if (existsSync(agentsSourceDir)) {
    const agentFiles = readdirSync(agentsSourceDir).filter(f => f.endsWith(".md"));
    totalFiles += agentFiles.length;
    
    if (!existsSync(agentsTargetDir)) {
      mkdirSync(agentsTargetDir, { recursive: true });
    }
    
    for (const file of agentFiles) {
      const sourcePath = join(agentsSourceDir, file);
      const targetPath = join(agentsTargetDir, file);
      try {
        copyFileSync(sourcePath, targetPath);
        console.log(`  ✓ Installed agent: ${file}`);
        successCount++;
      } catch (err) {
        console.error(`  ✗ Failed: ${file} - ${err.message}`);
      }
    }
  } else {
    console.error("  ✗ agents/ directory not found");
  }

  // 2. Install SKILL.md
  console.log("\n[2/3] Installing skill...");
  const skillSource = join(packageRoot, "SKILL.md");
  const skillTarget = join(skillTargetDir, "SKILL.md");
  totalFiles++;
  
  if (existsSync(skillSource)) {
    if (!existsSync(skillTargetDir)) {
      mkdirSync(skillTargetDir, { recursive: true });
    }
    try {
      copyFileSync(skillSource, skillTarget);
      console.log(`  ✓ Installed: SKILL.md`);
      successCount++;
    } catch (err) {
      console.error(`  ✗ Failed: SKILL.md - ${err.message}`);
    }
  } else {
    console.error("  ✗ SKILL.md not found");
  }

  // 3. Install references
  console.log("\n[3/3] Installing references...");
  const refsSourceDir = join(packageRoot, "references");
  const refsTargetDir = join(skillTargetDir, "references");
  
  if (existsSync(refsSourceDir)) {
    if (!existsSync(refsTargetDir)) {
      mkdirSync(refsTargetDir, { recursive: true });
    }
    
    const refFiles = readdirSync(refsSourceDir, { recursive: true }).filter(f => typeof f === "string");
    totalFiles += refFiles.length;
    
    for (const file of refFiles) {
      const sourcePath = join(refsSourceDir, file);
      const targetPath = join(refsTargetDir, file);
      const targetFileDir = join(refsTargetDir, file).replace(/\/[^\/]+$/, "");
      if (!existsSync(targetFileDir)) {
        mkdirSync(targetFileDir, { recursive: true });
      }
      try {
        copyFileSync(sourcePath, targetPath);
        console.log(`  ✓ Installed: references/${file}`);
        successCount++;
      } catch (err) {
        console.error(`  ✗ Failed: references/${file} - ${err.message}`);
      }
    }
  } else {
    console.log("  (references/ not found, skipping)");
  }

  // Summary
  console.log("\n========================================");
  if (successCount === totalFiles) {
    console.log(`✓ Successfully installed ${successCount} file(s)`);
    console.log(`\nAgent location: ${agentsTargetDir}`);
    console.log(`Skill location: ${skillTargetDir}`);
    console.log("\nTo use:");
    console.log("  @api-cyber-supervisor  - Start security testing");
    console.log("  skill({ name: \"api-security-testing\" })  - Load skill");
  } else {
    console.log(`⚠ Partially installed: ${successCount}/${totalFiles}`);
    process.exit(1);
  }
}

main();
