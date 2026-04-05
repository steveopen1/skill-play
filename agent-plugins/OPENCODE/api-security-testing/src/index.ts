import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin";
import { join } from "path";
import { existsSync } from "fs";

const SKILL_DIR = "skills/api-security-testing";
const CORE_DIR = `${SKILL_DIR}/core`;

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

const ApiSecurityTestingPlugin: Plugin = async (ctx) => {
  console.log("[api-security-testing] Plugin loaded");

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
          const result = await ctx.$`${cmd}`;
          return result.toString();
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
          const result = await ctx.$`${cmd}`;
          return result.toString();
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
          const result = await ctx.$`${cmd}`;
          return result.toString();
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
          const result = await ctx.$`${cmd}`;
          return result.toString();
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
          const result = await ctx.$`${cmd}`;
          return result.toString();
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
          const result = await ctx.$`${cmd}`;
          return result.toString();
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
          const result = await ctx.$`${cmd}`;
          return result.toString();
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
          const result = await ctx.$`${cmd}`;
          return result.toString();
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
          const result = await ctx.$`${cmd}`;
          return result.toString();
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
          const result = await ctx.$`${cmd}`;
          return result.toString();
        },
      }),
    },
  };
};

export default ApiSecurityTestingPlugin;
