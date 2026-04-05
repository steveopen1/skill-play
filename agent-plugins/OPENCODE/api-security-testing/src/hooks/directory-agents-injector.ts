import type { PluginInput } from "@opencode-ai/plugin";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const AGENTS_FILENAME = "AGENTS.md";
const AGENTS_DIR = ".config/opencode/agents";

export function createDirectoryAgentsInjectorHook(ctx: PluginInput) {
  function resolveAgentsDir(): string | null {
    const home = process.env.HOME || process.env.USERPROFILE;
    if (!home) return null;
    return join(home, AGENTS_DIR);
  }

  function findAgentsMdUp(startDir: string, agentsDir: string): string | null {
    let current = startDir;

    while (true) {
      const agentsPath = join(current, AGENTS_FILENAME);
      if (existsSync(agentsPath)) {
        return agentsPath;
      }

      if (current === agentsDir) break;
      const parent = dirname(current);
      if (parent === current) break;
      if (parent === "/" || parent === home) break;
      current = parent;
    }

    return null;
  }

  function getSessionKey(sessionID: string): string {
    return `api-sec-inject-${sessionID}`;
  }

  const injectedPaths = new Set<string>();

  const toolExecuteAfter = async (
    input: { tool: string; sessionID: string; callID: string },
    output: { title: string; output: string; metadata: unknown }
  ) => {
    const toolName = input.tool.toLowerCase();
    const agentsDir = resolveAgentsDir();
    
    if (!agentsDir || !existsSync(agentsDir)) return;

    if (toolName === "read") {
      const filePath = output.title;
      if (!filePath) return;

      const resolved = resolve(filePath);
      const dir = dirname(resolved);

      if (!dir.includes(agentsDir)) return;

      const cacheKey = getSessionKey(input.sessionID);
      if (injectedPaths.has(cacheKey + resolved)) return;

      const agentsPath = findAgentsMdUp(dir, agentsDir);
      if (!agentsPath) return;

      try {
        const content = readFileSync(agentsPath, "utf-8");
        output.output += `\n\n[Auto-injected from ${AGENTS_FILENAME}]\n${content}`;
        injectedPaths.add(cacheKey + resolved);
      } catch (err) {
        console.error("[api-security-testing] Failed to inject agents:", err);
      }
    }
  };

  const eventHandler = async (input: { event: { type: string; properties?: unknown } }) => {
    const { event } = input;

    if (event.type === "session.deleted" || event.type === "session.compacted") {
      const props = event.properties as Record<string, unknown> | undefined;
      let sessionID: string | undefined;

      if (event.type === "session.deleted") {
        sessionID = (props?.info as { id?: string })?.id;
      } else {
        sessionID = (props?.sessionID ?? (props?.info as { id?: string })?.id) as string | undefined;
      }

      if (sessionID) {
        const cacheKey = getSessionKey(sessionID);
        for (const key of injectedPaths.keys()) {
          if (key.startsWith(cacheKey)) {
            injectedPaths.delete(key);
          }
        }
      }
    }
  };

  return {
    "tool.execute.after": toolExecuteAfter,
    event: eventHandler,
  };
}