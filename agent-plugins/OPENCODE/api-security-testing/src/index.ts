import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin";
import { join, dirname, resolve } from "path";
import { existsSync, readFileSync } from "fs";

const SKILL_DIR = "skills/api-security-testing";
const CORE_DIR = `${SKILL_DIR}/core`;
const AGENTS_DIR = ".config/opencode/agents";
const AGENTS_FILENAME = "AGENTS.md";

function getSkillPath(ctx: { directory: string }): string {
  return join(ctx.directory, SKILL_DIR);
}

function getCorePath(ctx: { directory: string }): string {
  return join(ctx.directory, CORE_DIR);
}

function checkDeps(ctx: { directory: string }): string {
  const skillPath = getSkillPath(ctx);
  const reqFile = join(skillPath, "requirements.txt");
  if (existsSync(reqFile)) {
    return `pip install -q -r "${reqFile}" 2>/dev/null; `;
  }
  return "";
}

function getAgentsDir(): string {
  const home = process.env.HOME || process.env.USERPROFILE || "/root";
  return join(home, AGENTS_DIR);
}

function getInjectedAgentsPrompt(): string {
  const agentsDir = getAgentsDir();
  const agentsPath = join(agentsDir, "api-cyber-supervisor.md");
  
  if (!existsSync(agentsPath)) {
    return "";
  }

  try {
    const content = readFileSync(agentsPath, "utf-8");
    return `

[API Security Testing Agents Available]
When performing security testing tasks, you can use the following specialized agents:

${content}

To activate these agents, simply mention their name in your response (e.g., "@api-cyber-supervisor" to coordinate security testing).
`;
  } catch {
    return "";
  }
}

async function execShell(ctx: unknown, cmd: string): Promise<string> {
  const shell = ctx as { $: (strings: TemplateStringsArray, ...expr: unknown[]) => Promise<{ toString(): string }> };
  const result = await shell.$`${cmd}`;
  return result.toString();
}

const ApiSecurityTestingPlugin: Plugin = async (ctx) => {
  console.log("[api-security-testing] Plugin loaded");

  const injectedSessions = new Set<string>();

  return {
    tool: {
      api_security_scan: tool({
        description: "完整 API 安全扫描。参数: target(目标URL), scan_type(full/quick/targeted)",
        args: {
          target: tool.schema.string(),
          scan_type: tool.schema.enum(["full", "quick", "targeted"]).optional(),
        },
        async execute(args, ctx) {
          const deps = checkDeps(ctx);
          const corePath = getCorePath(ctx);
          const cmd = `${deps}python3 -c "
import sys
sys.path.insert(0, '${corePath}')
from deep_api_tester_v55 import DeepAPITesterV55
tester = DeepAPITesterV55(target='${args.target}', headless=True)
results = tester.run_test()
print(results)
"`;
          return await execShell(ctx, cmd);
        },
      }),

      api_fuzz_test: tool({
        description: "API 模糊测试。参数: endpoint(端点URL), method(HTTP方法)",
        args: {
          endpoint: tool.schema.string(),
          method: tool.schema.enum(["GET", "POST", "PUT", "DELETE", "PATCH"]).optional(),
        },
        async execute(args, ctx) {
          const deps = checkDeps(ctx);
          const corePath = getCorePath(ctx);
          const cmd = `${deps}python3 -c "
import sys
sys.path.insert(0, '${corePath}')
from api_fuzzer import APIFuzzer
fuzzer = APIFuzzer('${args.endpoint}')
results = fuzzer.fuzz(method='${args.method || 'GET'}')
print(results)
"`;
          return await execShell(ctx, cmd);
        },
      }),

      vuln_verify: tool({
        description: "漏洞验证。参数: vuln_type(漏洞类型), endpoint(端点)",
        args: {
          vuln_type: tool.schema.string(),
          endpoint: tool.schema.string(),
        },
        async execute(args, ctx) {
          const deps = checkDeps(ctx);
          const corePath = getCorePath(ctx);
          const cmd = `${deps}python3 -c "
import sys
sys.path.insert(0, '${corePath}')
from verifiers.vuln_verifier import VulnVerifier
verifier = VulnVerifier()
result = verifier.verify('${args.vuln_type}', '${args.endpoint}')
print(result)
"`;
          return await execShell(ctx, cmd);
        },
      }),

      browser_collect: tool({
        description: "浏览器采集动态内容。参数: url(目标URL)",
        args: {
          url: tool.schema.string(),
        },
        async execute(args, ctx) {
          const deps = checkDeps(ctx);
          const corePath = getCorePath(ctx);
          const cmd = `${deps}python3 -c "
import sys
sys.path.insert(0, '${corePath}')
from collectors.browser_collect import BrowserCollector
collector = BrowserCollector(headless=True)
endpoints = collector.collect('${args.url}')
print(f'发现 {len(endpoints)} 个端点:')
for ep in endpoints:
    print(ep)
"`;
          return await execShell(ctx, cmd);
        },
      }),

      js_parse: tool({
        description: "解析 JavaScript 文件。参数: file_path(文件路径)",
        args: {
          file_path: tool.schema.string(),
        },
        async execute(args, ctx) {
          const deps = checkDeps(ctx);
          const corePath = getCorePath(ctx);
          const cmd = `${deps}python3 -c "
import sys
sys.path.insert(0, '${corePath}')
from collectors.js_parser import JSParser
parser = JSParser()
endpoints = parser.parse_file('${args.file_path}')
print(f'从 JS 发现 {len(endpoints)} 个端点')
"`;
          return await execShell(ctx, cmd);
        },
      }),

      graphql_test: tool({
        description: "GraphQL 安全测试。参数: endpoint(GraphQL端点)",
        args: {
          endpoint: tool.schema.string(),
        },
        async execute(args, ctx) {
          const deps = checkDeps(ctx);
          const corePath = getCorePath(ctx);
          const cmd = `${deps}python3 -c "
import sys
sys.path.insert(0, '${corePath}')
from smart_analyzer import SmartAnalyzer
analyzer = SmartAnalyzer()
result = analyzer.graphql_test('${args.endpoint}')
print(result)
"`;
          return await execShell(ctx, cmd);
        },
      }),

      cloud_storage_test: tool({
        description: "云存储安全测试。参数: bucket_url(存储桶URL)",
        args: {
          bucket_url: tool.schema.string(),
        },
        async execute(args, ctx) {
          const deps = checkDeps(ctx);
          const corePath = getCorePath(ctx);
          const cmd = `${deps}python3 -c "
import sys
sys.path.insert(0, '${corePath}')
from cloud_storage_tester import CloudStorageTester
tester = CloudStorageTester()
result = tester.full_test('${args.bucket_url}')
print(result)
"`;
          return await execShell(ctx, cmd);
        },
      }),

      idor_test: tool({
        description: "IDOR 越权测试。参数: endpoint, resource_id",
        args: {
          endpoint: tool.schema.string(),
          resource_id: tool.schema.string(),
        },
        async execute(args, ctx) {
          const deps = checkDeps(ctx);
          const corePath = getCorePath(ctx);
          const cmd = `${deps}python3 -c "
import sys
sys.path.insert(0, '${corePath}')
from testers.idor_tester import IDORTester
tester = IDORTester()
result = tester.test('${args.endpoint}', '${args.resource_id}')
print(result)
"`;
          return await execShell(ctx, cmd);
        },
      }),

      sqli_test: tool({
        description: "SQL 注入测试。参数: endpoint, param",
        args: {
          endpoint: tool.schema.string(),
          param: tool.schema.string(),
        },
        async execute(args, ctx) {
          const deps = checkDeps(ctx);
          const corePath = getCorePath(ctx);
          const cmd = `${deps}python3 -c "
import sys
sys.path.insert(0, '${corePath}')
from testers.sqli_tester import SQLiTester
tester = SQLiTester()
result = tester.test('${args.endpoint}', '${args.param}')
print(result)
"`;
          return await execShell(ctx, cmd);
        },
      }),

      auth_test: tool({
        description: "认证安全测试。参数: endpoint",
        args: {
          endpoint: tool.schema.string(),
        },
        async execute(args, ctx) {
          const deps = checkDeps(ctx);
          const corePath = getCorePath(ctx);
          const cmd = `${deps}python3 -c "
import sys
sys.path.insert(0, '${corePath}')
from testers.auth_tester import AuthTester
tester = AuthTester()
result = tester.test('${args.endpoint}')
print(result)
"`;
          return await execShell(ctx, cmd);
        },
      }),
    },

    "chat.message": async (input, output) => {
      const sessionID = input.sessionID;
      
      if (!injectedSessions.has(sessionID)) {
        injectedSessions.add(sessionID);
        
        const agentsPrompt = getInjectedAgentsPrompt();
        if (agentsPrompt) {
          const parts = output.parts as Array<{ type: string; text?: string }>;
          const textPart = parts.find(p => p.type === "text");
          if (textPart && textPart.text) {
            textPart.text += agentsPrompt;
          }
        }
      }
    },

    "tool.execute.after": async (input, output) => {
      const toolName = input.tool.toLowerCase();
      const agentsDir = getAgentsDir();
      
      if (!existsSync(agentsDir)) return;

      if (toolName === "read") {
        const filePath = output.title;
        if (!filePath) return;

        const resolved = resolve(filePath);
        const dir = dirname(resolved);

        if (!dir.includes(agentsDir)) return;

        const agentsPath = join(agentsDir, AGENTS_FILENAME);
        if (!existsSync(agentsPath)) return;

        try {
          const content = readFileSync(agentsPath, "utf-8");
          output.output += `\n\n[Agents Definition]\n${content}`;
        } catch (err) {
          console.error("[api-security-testing] Failed to inject agents:", err);
        }
      }
    },

    event: async (input) => {
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
          injectedSessions.delete(sessionID);
        }
      }
    },
  };
};

export default ApiSecurityTestingPlugin;
