import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin";
import type { AgentConfig } from "@opencode-ai/sdk";
import { join } from "path";

const CYBER_SUPERVISOR_PROMPT = `你是 API 安全测试的**赛博监工**，代号"渗透测试员P9"。

## 职责

1. **永不停止** - 任何线索都要追到底
2. **自动化循环** - 不等待用户指令
3. **压力升级** - 遇到失败自动换方法
4. **智能委派** - 使用 delegate_task 委派给 probing-miner 和 resource-specialist

## 可用工具（通过 Skill）

- api_scan: 对目标进行完整 API 安全扫描
- api_fuzz: 对特定端点进行模糊测试
- browser_collect: 使用浏览器采集动态内容
- vuln_verify: 验证漏洞是否存在
- cloud_storage_test: 测试云存储安全
- graphql_test: GraphQL 安全测试

## 工作流程

发现线索 → 调用工具 → 收集结果 → 继续追查
    ↓
进度追踪 → 压力升级(L1-L4) → 永不停止

## 漏洞类型

- SQL 注入: references/vulnerabilities/01-sqli-tests.md
- IDOR: references/vulnerabilities/04-idor-tests.md
- JWT 漏洞: references/vulnerabilities/03-jwt-tests.md
- 敏感数据: references/vulnerabilities/05-sensitive-data-tests.md
- 认证漏洞: references/vulnerabilities/10-auth-tests.md
- GraphQL: references/vulnerabilities/11-graphql-tests.md
- SSRF: references/vulnerabilities/12-ssrf-tests.md`;

const PROBING_MINER_PROMPT = `你是**探测挖掘专家**，专注于对 API 端点进行漏洞挖掘。

## 职责

1. **针对性测试** - 根据端点类型选择合适的测试方法
2. **漏洞验证** - 对发现的漏洞进行验证并生成 PoC
3. **调用工具** - 使用 api_scan, api_fuzz, vuln_verify 等工具

## 可用工具

- api_scan: 完整 API 安全扫描
- api_fuzz: 端点模糊测试
- vuln_verify: 漏洞验证
- cloud_storage_test: 云存储测试
- graphql_test: GraphQL 测试

## 漏洞测试指南

- SQL 注入: references/vulnerabilities/01-sqli-tests.md
- 用户枚举: references/vulnerabilities/02-user-enum-tests.md
- JWT 安全: references/vulnerabilities/03-jwt-tests.md
- IDOR: references/vulnerabilities/04-idor-tests.md
- 敏感数据: references/vulnerabilities/05-sensitive-data-tests.md`;

const RESOURCE_SPECIALIST_PROMPT = `你是**资源探测专家**，专注于采集和发现 API 端点。

## 职责

1. **动态采集** - 使用浏览器采集 API 端点
2. **静态分析** - 从 JS 文件和源码中提取端点
3. **模式识别** - 识别 API 的 URL 模式和参数结构

## 可用工具

- browser_collect: 使用 Playwright 采集动态内容
- js_parse: 解析 JavaScript 文件提取端点
- url_discover: 发现隐藏 URL

## 采集技术

### 方法1: Playwright 浏览器采集
使用 Playwright 打开页面，拦截所有 XHR/Fetch 请求

### 方法2: JavaScript 文件分析
从 JS 文件中提取 API 端点路径和参数命名模式

### 方法3: 目录和文件探测
常见路径：/api/v1/*, /graphql, /swagger, /.well-known/*`;

const ApiSecurityTestingPlugin: Plugin = async (ctx) => {
  return {
    tool: {
      api_security_scan: tool({
        description: "对目标进行完整的 API 安全扫描。参数：target(目标URL), scan_type(full/quick/targeted), vulnerabilities(要检测的漏洞类型数组)",
        args: {
          target: tool.schema.string(),
          scan_type: tool.schema.enum(["full", "quick", "targeted"]).optional(),
          vulnerabilities: tool.schema.array(tool.schema.string()).optional(),
        },
        async execute(args, context) {
          const skillPath = join(context.directory, "skills/api-security-testing");
          const cmd = `cd ${skillPath} && pip install -q -r requirements.txt 2>/dev/null; python3 -c "
import sys
sys.path.insert(0, 'core')
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
        description: "对特定 API 端点进行模糊测试。参数：endpoint(端点URL), method(HTTP方法)",
        args: {
          endpoint: tool.schema.string(),
          method: tool.schema.enum(["GET", "POST", "PUT", "DELETE", "PATCH"]).optional(),
        },
        async execute(args, context) {
          const skillPath = join(context.directory, "skills/api-security-testing");
          const cmd = `cd ${skillPath} && python3 -c "
import sys
sys.path.insert(0, 'core')
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
        description: "验证漏洞是否存在。参数：vuln_type(漏洞类型), endpoint(端点), evidence(可选证据)",
        args: {
          vuln_type: tool.schema.string(),
          endpoint: tool.schema.string(),
          evidence: tool.schema.string().optional(),
        },
        async execute(args, context) {
          const skillPath = join(context.directory, "skills/api-security-testing");
          const cmd = `cd ${skillPath} && python3 -c "
import sys
sys.path.insert(0, 'core')
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
        description: "使用 Playwright 浏览器采集动态内容。参数：url(目标URL), wait_for(等待元素)",
        args: {
          url: tool.schema.string(),
          wait_for: tool.schema.string().optional(),
        },
        async execute(args, context) {
          const skillPath = join(context.directory, "skills/api-security-testing");
          const cmd = `cd ${skillPath} && python3 -c "
import sys
sys.path.insert(0, 'core')
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

      cloud_storage_test: tool({
        description: "测试云存储安全。参数：bucket_url(存储桶URL)",
        args: {
          bucket_url: tool.schema.string(),
        },
        async execute(args, context) {
          const skillPath = join(context.directory, "skills/api-security-testing");
          const cmd = `cd ${skillPath} && python3 -c "
import sys
sys.path.insert(0, 'core')
from cloud_storage_tester import CloudStorageTester
tester = CloudStorageTester()
result = tester.full_test('${args.bucket_url}')
print(result)
"`;
          const result = await ctx.$`${cmd}`;
          return result.toString();
        },
      }),

      graphql_security_test: tool({
        description: "测试 GraphQL 安全。参数：endpoint(GraphQL端点)",
        args: {
          endpoint: tool.schema.string(),
        },
        async execute(args, context) {
          const skillPath = join(context.directory, "skills/api-security-testing");
          const cmd = `cd ${skillPath} && python3 -c "
import sys
sys.path.insert(0, 'core')
from smart_analyzer import SmartAnalyzer
analyzer = SmartAnalyzer()
result = analyzer.graphql_test('${args.endpoint}')
print(result)
"`;
          const result = await ctx.$`${cmd}`;
          return result.toString();
        },
      }),
    },

    config: async (config) => {
      const agentConfig = config.agent as Record<string, AgentConfig> | undefined;
      
      if (!agentConfig) {
        config.agent = {};
      }

      (config.agent as Record<string, AgentConfig>)["cyber-supervisor"] = {
        description: "API安全测试的赛博监工。永不停止任何线索，自动循环执行，遇到失败自动委派 probing-miner 和 resource-specialist 进行探测。",
        mode: "subagent",
        prompt: CYBER_SUPERVISOR_PROMPT,
      };

      (config.agent as Record<string, AgentConfig>)["probing-miner"] = {
        description: "探测挖掘专家。使用专业测试技术，引用漏洞测试指南进行针对性漏洞挖掘和验证。",
        mode: "subagent",
        prompt: PROBING_MINER_PROMPT,
      };

      (config.agent as Record<string, AgentConfig>)["resource-specialist"] = {
        description: "资源探测专家。专注于采集和发现 API 端点，使用动态和静态分析技术提取所有可能的攻击面。",
        mode: "subagent",
        prompt: RESOURCE_SPECIALIST_PROMPT,
      };
    },
  };
};

export default ApiSecurityTestingPlugin;
