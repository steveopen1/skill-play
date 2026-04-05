#!/usr/bin/env node

/**
 * preuninstall.mjs - API Security Testing Plugin
 * 
 * Removes installed files when the package is uninstalled.
 */

import { existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function getOpencodeBaseDir() {
  const home = process.env.HOME || process.env.USERPROFILE || "/root";
  return join(home, ".config", "opencode");
}

function deleteFile(filePath) {
  try {
    if (existsSync(filePath)) {
      rmSync(filePath);
      console.log(`  ✓ Removed: ${filePath}`);
      return true;
    }
  } catch (err) {
    console.error(`  ✗ Failed to remove: ${filePath} - ${err.message}`);
  }
  return false;
}

function deleteDirectory(dirPath) {
  try {
    if (existsSync(dirPath)) {
      rmSync(dirPath, { recursive: true });
      console.log(`  ✓ Removed directory: ${dirPath}`);
      return true;
    }
  } catch (err) {
    console.error(`  ✗ Failed to remove directory: ${dirPath} - ${err.message}`);
  }
  return false;
}

function main() {
  const baseDir = getOpencodeBaseDir();
  const agentsDir = join(baseDir, "agents");
  const skillDir = join(baseDir, "skills", "api-security-testing");
  
  console.log("[api-security-testing] Uninstalling...");
  console.log(`  Base directory: ${baseDir}`);

  let removedCount = 0;
  let totalCount = 0;

  // 1. Remove agent files
  console.log("\n[1/2] Removing agents...");
  if (existsSync(agentsDir)) {
    const agentFiles = readdirSync(agentsDir).filter(f => f.endsWith(".md"));
    totalCount += agentFiles.length;
    
    for (const file of agentFiles) {
      const filePath = join(agentsDir, file);
      // Only remove our agents (prefix with our plugin name)
      if (file.startsWith("api-")) {
        if (deleteFile(filePath)) removedCount++;
      } else {
        console.log(`  - Skipped (not our agent): ${file}`);
      }
    }
  }

  // 2. Remove skill directory
  console.log("\n[2/2] Removing skill...");
  if (existsSync(skillDir)) {
    if (deleteDirectory(skillDir)) {
      removedCount++;
    }
  }

  // Summary
  console.log("\n========================================");
  console.log(`Uninstall complete.`);
  console.log("\nNote: If you reinstall the package, the postinstall script will re-install the files.");
}

main();
