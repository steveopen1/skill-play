#!/usr/bin/env node

/**
 * postinstall.mjs - API Security Testing Plugin
 * 
 * Installs:
 * 1. agents to ~/.config/opencode/agents/
 * 2. SKILL.md and references to ~/.config/opencode/skills/api-security-testing/
 */

import { copyFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = join(__filename, "..");

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

  let totalInstalled = 0;
  let totalFailed = 0;

  // 1. Install agents
  console.log("\n[1/3] Installing agents...");
  if (existsSync(agentsSourceDir)) {
    if (!existsSync(agentsTargetDir)) {
      mkdirSync(agentsTargetDir, { recursive: true });
    }
    
    const files = readdirSync(agentsSourceDir).filter(f => f.endsWith(".md"));
    for (const file of files) {
      try {
        copyFileSync(join(agentsSourceDir, file), join(agentsTargetDir, file));
        console.log(`  ✓ ${file}`);
        totalInstalled++;
      } catch (err) {
        console.error(`  ✗ ${file}: ${err.message}`);
        totalFailed++;
      }
    }
  }

  // 2. Install SKILL.md
  console.log("\n[2/3] Installing SKILL.md...");
  const skillSource = join(packageRoot, "SKILL.md");
  if (existsSync(skillSource)) {
    if (!existsSync(skillTargetDir)) {
      mkdirSync(skillTargetDir, { recursive: true });
    }
    try {
      copyFileSync(skillSource, join(skillTargetDir, "SKILL.md"));
      console.log("  ✓ SKILL.md");
      totalInstalled++;
    } catch (err) {
      console.error(`  ✗ SKILL.md: ${err.message}`);
      totalFailed++;
    }
  }

  // 3. Install references
  console.log("\n[3/3] Installing references...");
  const refsSourceDir = join(packageRoot, "references");
  const refsTargetDir = join(skillTargetDir, "references");
  if (existsSync(refsSourceDir)) {
    if (!existsSync(refsTargetDir)) {
      mkdirSync(refsTargetDir, { recursive: true });
    }
    
    function copyDir(src, dest) {
      const items = readdirSync(src);
      for (const item of items) {
        const srcPath = join(src, item);
        const destPath = join(dest, item);
        try {
          copyFileSync(srcPath, destPath);
          totalInstalled++;
        } catch {
          if (existsSync(srcPath) && !srcPath.endsWith(".md")) {
            mkdirSync(destPath, { recursive: true });
            copyDir(srcPath, destPath);
          }
        }
      }
    }
    
    try {
      copyDir(refsSourceDir, refsTargetDir);
      console.log("  ✓ references/");
      totalInstalled++;
    } catch (err) {
      console.error(`  ✗ references/: ${err.message}`);
      totalFailed++;
    }
  }

  console.log(`\n========================================`);
  if (totalFailed === 0) {
    console.log(`✓ Installed ${totalInstalled} file(s)`);
    console.log(`\nAgents: ${agentsTargetDir}`);
    console.log(`Skill: ${skillTargetDir}`);
  } else {
    console.log(`⚠ Installed ${totalInstalled}, failed ${totalFailed}`);
    process.exit(1);
  }
}

main();
