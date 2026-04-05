import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin";

function getCorePath(directory: string): string {
  return `${directory}/skills/api-security-testing/core`;
}

const ApiSecurityTestingPlugin: Plugin = async (ctx) => {
  return {
    tool: {
      api_security_scan: tool({
        description: "完整 API 安全扫描",
        args: {
          target: tool.schema.string(),
          scan_type: tool.schema.enum(["full", "quick", "targeted"]).optional(),
        },
        async execute(args, ctx) {
          const corePath = getCorePath(ctx.directory);
          const script = `
import sys
sys.path.insert(0, '${corePath}')
try:
    from deep_api_tester_v55 import DeepAPITesterV55
    tester = DeepAPITesterV55(target='${args.target}', headless=True)
    print(tester.run_test())
except Exception as e:
    print(f"Error: {e}")
`;
          const result = await ctx.$`python3 -c ${script}`;
          return result.toString();
        },
      }),

      api_fuzz_test: tool({
        description: "API 模糊测试",
        args: {
          endpoint: tool.schema.string(),
          method: tool.schema.enum(["GET", "POST", "PUT", "DELETE", "PATCH"]).optional(),
        },
        async execute(args, ctx) {
          const corePath = getCorePath(ctx.directory);
          const script = `
import sys
sys.path.insert(0, '${corePath}')
try:
    from api_fuzzer import APIFuzzer
    fuzzer = APIFuzzer('${args.endpoint}')
    print(fuzzer.fuzz(method='${args.method || "GET"}'))
except Exception as e:
    print(f"Error: {e}")
`;
          const result = await ctx.$`python3 -c ${script}`;
          return result.toString();
        },
      }),

      vuln_verify: tool({
        description: "漏洞验证",
        args: {
          vuln_type: tool.schema.string(),
          endpoint: tool.schema.string(),
        },
        async execute(args, ctx) {
          const corePath = getCorePath(ctx.directory);
          const script = `
import sys
sys.path.insert(0, '${corePath}')
try:
    from verifiers.vuln_verifier import VulnVerifier
    verifier = VulnVerifier()
    print(verifier.verify('${args.vuln_type}', '${args.endpoint}'))
except Exception as e:
    print(f"Error: {e}")
`;
          const result = await ctx.$`python3 -c ${script}`;
          return result.toString();
        },
      }),

      browser_collect: tool({
        description: "浏览器采集动态内容",
        args: {
          url: tool.schema.string(),
        },
        async execute(args, ctx) {
          const corePath = getCorePath(ctx.directory);
          const script = `
import sys
sys.path.insert(0, '${corePath}')
try:
    from collectors.browser_collect import BrowserCollector
    collector = BrowserCollector(headless=True)
    endpoints = collector.collect('${args.url}')
    print(f'发现 {len(endpoints)} 个端点')
    for ep in endpoints:
        print(ep)
except Exception as e:
    print(f"Error: {e}")
`;
          const result = await ctx.$`python3 -c ${script}`;
          return result.toString();
        },
      }),

      graphql_test: tool({
        description: "GraphQL 安全测试",
        args: {
          endpoint: tool.schema.string(),
        },
        async execute(args, ctx) {
          const corePath = getCorePath(ctx.directory);
          const script = `
import sys
sys.path.insert(0, '${corePath}')
try:
    from smart_analyzer import SmartAnalyzer
    analyzer = SmartAnalyzer()
    print(analyzer.graphql_test('${args.endpoint}'))
except Exception as e:
    print(f"Error: {e}")
`;
          const result = await ctx.$`python3 -c ${script}`;
          return result.toString();
        },
      }),

      sqli_test: tool({
        description: "SQL 注入测试",
        args: {
          endpoint: tool.schema.string(),
          param: tool.schema.string(),
        },
        async execute(args, ctx) {
          const corePath = getCorePath(ctx.directory);
          const script = `
import sys
sys.path.insert(0, '${corePath}')
try:
    from testers.sqli_tester import SQLiTester
    tester = SQLiTester()
    print(tester.test('${args.endpoint}', '${args.param}'))
except Exception as e:
    print(f"Error: {e}")
`;
          const result = await ctx.$`python3 -c ${script}`;
          return result.toString();
        },
      }),

      idor_test: tool({
        description: "IDOR 越权测试",
        args: {
          endpoint: tool.schema.string(),
          resource_id: tool.schema.string(),
        },
        async execute(args, ctx) {
          const corePath = getCorePath(ctx.directory);
          const script = `
import sys
sys.path.insert(0, '${corePath}')
try:
    from testers.idor_tester import IDORTester
    tester = IDORTester()
    print(tester.test('${args.endpoint}', '${args.resource_id}'))
except Exception as e:
    print(f"Error: {e}")
`;
          const result = await ctx.$`python3 -c ${script}`;
          return result.toString();
        },
      }),
    },
  };
};

export default ApiSecurityTestingPlugin;
