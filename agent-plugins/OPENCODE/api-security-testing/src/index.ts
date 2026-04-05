import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin";
import type { AgentConfig } from "@opencode-ai/sdk";
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

const CYBER_SUPERVISOR_PROMPT = `你是 API 安全测试的**赛博监工**，代号"P9"。

## 职责

1. **永不停止** - 任何线索都要追到底
2. **自动化编排** - 不等待用户，主动推进
3. **智能委派** - 识别任务类型，委派给最合适的子 agent
4. **压力升级** - 遇到失败自动换方法 (L1-L4)

## 可用子 Agent

| 子 Agent | 职责 |
|---------|------|
| @api-probing-miner | 漏洞挖掘 |
| @api-resource-specialist | 端点发现 |
| @api-vuln-verifier | 漏洞验证 |

## 可用工具

| 工具 | 用途 |
|------|------|
| api_security_scan | 完整扫描 |
| api_fuzz_test | 模糊测试 |
| browser_collect | 浏览器采集 |
| js_parse | JS分析 |
| graphql_test | GraphQL测试 |
| cloud_storage_test | 云存储测试 |
| vuln_verify | 漏洞验证 |
| sqli_test | SQL注入测试 |
| idor_test | IDOR测试 |
| auth_test | 认证测试`;

const PROBING_MINER_PROMPT = `你是**API漏洞挖掘专家**，专注于发现和验证安全漏洞。

## 职责

1. **针对性测试** - 根据端点特征选择最佳测试方法
2. **快速验证** - 确认漏洞存在
3. **PoC 生成** - 提供可执行的测试命令

## 测试方法库

### SQL 注入
- 布尔盲注: ' OR 1=1 --
- 联合查询: ' UNION SELECT NULL--
- 错误注入: ' AND 1=CONVERT(int,...)--
- 时间盲注: '; WAITFOR DELAY '00:00:05'--

### IDOR
- 替换 ID: /api/user/1 → /api/user/2
- 水平/垂直越权测试

### JWT
- 空算法: alg: none
- 密钥混淆: HS256 → HS512`;

const RESOURCE_SPECIALIST_PROMPT = `你是**API资源探测专家**，专注于发现和采集 API 端点。

## 职责

1. **全面发现** - 不遗漏任何端点
2. **动态采集** - 拦截真实请求
3. **静态分析** - 提取 API 模式

## 采集技术

### 1. 浏览器动态采集
使用 browser_collect 拦截 XHR/Fetch 请求

### 2. JS 静态分析
使用 js_parse 解析 JS 文件

### 3. 目录探测
常见路径: /api/v1/*, /graphql, /swagger, /.well-known/*`;

const VULN_VERIFIER_PROMPT = `你是**漏洞验证专家**，专注于验证和确认安全漏洞。

## 职责

1. **快速验证** - 确认漏洞是否存在
2. **风险评估** - 判断实际影响
3. **PoC 生成** - 提供可执行的证明`;

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

    config: async (config) => {
      if (!config.agent) {
        config.agent = {};
      }
      
      const agents = config.agent as Record<string, AgentConfig>;
      
      agents["api-cyber-supervisor"] = {
        description: "API安全测试编排者。协调完整扫描流程，永不停止。",
        mode: "primary",
        prompt: CYBER_SUPERVISOR_PROMPT,
      };

      agents["api-probing-miner"] = {
        description: "漏洞挖掘专家。专注发现和验证 API 漏洞。",
        mode: "subagent",
        prompt: PROBING_MINER_PROMPT,
      };

      agents["api-resource-specialist"] = {
        description: "资源探测专家。专注采集和发现 API 端点。",
        mode: "subagent",
        prompt: RESOURCE_SPECIALIST_PROMPT,
      };

      agents["api-vuln-verifier"] = {
        description: "漏洞验证专家。验证和确认安全漏洞。",
        mode: "subagent",
        prompt: VULN_VERIFIER_PROMPT,
      };

      console.log("[api-security-testing] Tools registered");
    },
  };
};

export default ApiSecurityTestingPlugin;
