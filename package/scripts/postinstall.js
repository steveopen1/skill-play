import { existsSync, mkdirSync, cpSync, rmSync, readdirSync, statSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageRoot = __dirname;

const OPENCODE_DIR = process.env.OPENCODE_CONFIG_DIR || join(process.env.HOME || "/root", ".config/opencode");
const SKILL_DIR = join(OPENCODE_DIR, "skills/api-security-testing");

function copyRecursive(src, dest) {
  if (!existsSync(src)) {
    console.warn(`[api-security-testing] Warning: ${src} does not exist, skipping`);
    return;
  }
  
  const stat = statSync(src);
  if (stat.isDirectory()) {
    if (!existsSync(dest)) {
      mkdirSync(dest, { recursive: true });
    }
    for (const entry of readdirSync(src)) {
      copyRecursive(join(src, entry), join(dest, entry));
    }
  } else {
    cpSync(src, dest, { force: true });
  }
}

console.log("[api-security-testing] Setting up skill files...");

try {
  copyRecursive(join(packageRoot, "core"), join(SKILL_DIR, "core"));
  copyRecursive(join(packageRoot, "references"), join(SKILL_DIR, "references"));
  
  const skillMdSrc = join(packageRoot, "SKILL.md");
  if (existsSync(skillMdSrc)) {
    cpSync(skillMdSrc, join(SKILL_DIR, "SKILL.md"), { force: true });
  }
  
  console.log("[api-security-testing] Skill files installed to:", SKILL_DIR);
} catch (error) {
  console.error("[api-security-testing] Error during installation:", error.message);
  process.exit(1);
}
