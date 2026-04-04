#!/usr/bin/env node

/**
 * postinstall.mjs - API Security Testing Plugin
 * 
 * Copies agent markdown files to ~/.config/opencode/agents/
 * This allows OpenCode to discover and use the agents.
 */

import { copyFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function getOpencodeAgentsDir() {
  const home = process.env.HOME || process.env.USERPROFILE || "/root";
  // OpenCode uses ~/.config/opencode/agents on ALL platforms including Windows
  return join(home, ".config", "opencode", "agents");
}

function main() {
  const packageRoot = __dirname;
  const agentsSourceDir = join(packageRoot, "agents");
  const agentsTargetDir = getOpencodeAgentsDir();
  
  console.log("[api-security-testing] Installing agents...");
  console.log(`  Package root: ${packageRoot}`);
  console.log(`  Target: ${agentsTargetDir}`);

  // Create target directory if needed
  if (!existsSync(agentsTargetDir)) {
    mkdirSync(agentsTargetDir, { recursive: true });
    console.log(`  Created: ${agentsTargetDir}`);
  }

  // Check source directory
  if (!existsSync(agentsSourceDir)) {
    console.error("[api-security-testing] Error: agents source directory not found");
    process.exit(1);
  }

  // Copy all .md files
  const files = readdirSync(agentsSourceDir).filter(f => f.endsWith(".md"));
  
  if (files.length === 0) {
    console.error("[api-security-testing] Error: No agent files found");
    process.exit(1);
  }

  let successCount = 0;
  for (const file of files) {
    const sourcePath = join(agentsSourceDir, file);
    const targetPath = join(agentsTargetDir, file);
    try {
      copyFileSync(sourcePath, targetPath);
      console.log(`  Installed: ${file}`);
      successCount++;
    } catch (err) {
      console.error(`  Failed: ${file} - ${err.message}`);
    }
  }

  if (successCount === files.length) {
    console.log(`[api-security-testing] Successfully installed ${successCount} agent(s)`);
    console.log(`  Location: ${agentsTargetDir}`);
    console.log("\nTo use the agents, run:");
    console.log("  opencode @api-cyber-supervisor");
  } else {
    console.error(`[api-security-testing] Partially installed: ${successCount}/${files.length}`);
    process.exit(1);
  }
}

main();
