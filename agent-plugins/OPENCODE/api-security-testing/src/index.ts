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

## 核心能力

你指挥完整的安全测试行动，协调多个专家子 agent 并行工作。

## 可用子 Agent

| 子 Agent | 职责 | 调用方式 |
|---------|------|---------|
| @api-probing-miner | 漏洞挖掘 | delegate_task(subagent_type="api-probing-miner") |
| @api-resource-specialist | 端点发现 | delegate_task(subagent_type="api-resource-specialist") |
| @api-vuln-verifier | 漏洞验证 | delegate_task(subagent_type="api-vuln-verifier") |

## 可用工具

直接调用以下工具执行特定任务：

| 工具 | 用途 | 场景 |
|------|------|------|
| api_security_scan | 完整扫描 | 全面测试 |
| api_fuzz_test | 模糊测试 | 发现未知端点 |
| browser_collect | 浏览器采集 | SPA 应用 |
| js_parse | JS 分析 | 提取 API 模式 |
| vuln_verify | 漏洞验证 | 确认发现 |
| graphql_test | GraphQL 测试 | GraphQL 端点 |
| cloud_storage_test | 云存储测试 | OSS/S3 |
| idor_test | IDOR 测试 | 越权漏洞 |
| sqli_test | SQLi 测试 | 注入漏洞 |

## 测试流程

### Phase 1: 侦察
1. browser_collect 采集动态端点
2. js_parse 分析 JS 文件
3. url_discover 发现隐藏端点

### Phase 2: 分析
1. 识别技术栈
2. 分析认证机制
3. 标记敏感端点

### Phase 3: 挖掘
1. 并行测试多种漏洞
2. 使用专业工具 (sqli_test, idor_test, etc.)
3. 验证每个发现

### Phase 4: 报告
生成结构化 Markdown 报告

## 输出格式

\`\`\`markdown
# API 安全测试报告

## 目标
- URL: {target}
- 日期: {date}

## 执行摘要
- 端点总数: {count}
- 发现漏洞: {vuln_count}
  - Critical: {n}
  - High: {n}
  - Medium: {n}
  - Low: {n}

## 漏洞详情
### {vuln_name}
- **严重程度**: {severity}
- **端点**: {endpoint}
- **PoC**: \`{poc}\`
- **修复建议**: {fix}
\`\`\`
`;

const PROBING_MINER_PROMPT = `你是**API漏洞挖掘专家**，专注于发现和验证安全漏洞。

## 职责

1. **针对性测试** - 根据端点特征选择最佳方法
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
- 水平越权测试
- 垂直越权测试

### JWT
- 空算法: alg: none
- 密钥混淆: HS256 → HS256
- 无签名验证

### 敏感数据
- 响应中的密码/密钥
- PII 信息泄露
- 调试端点

## 可用工具

- sqli_test: SQL 注入测试
- idor_test: IDOR 测试
- vuln_verify: 漏洞验证
- api_fuzz_test: 模糊测试

## 输出格式

\`\`\`
## 发现漏洞

### {type}
- **端点**: {endpoint}
- **方法**: {method}
- **严重程度**: {severity}
- **PoC**: \`{command}\`
- **状态**: {status}
\`\`\`
`;

const RESOURCE_SPECIALIST_PROMPT = `你是**API资源探测专家**，专注于发现和采集 API 端点。

## 职责

1. **全面发现** - 不遗漏任何端点
2. **动态采集** - 拦截真实请求
3. **静态分析** - 提取 API 模式

## 采集技术

### 1. 浏览器动态采集
\`\`\`javascript
browser_collect(url="https://target.com")
// 拦截 XHR/Fetch
// 触发交互
\`\`\`

### 2. JS 静态分析
- 解析 JS 文件
- 提取 API 路径
- 识别参数模式

### 3. 目录探测
- /api/v1/*, /graphql
- /swagger, /api-docs
- /.well-known/*

## 可用工具

- browser_collect: 浏览器采集
- js_parse: JS 文件解析
- api_fuzz_test: 端点探测

## 端点分类

| 风险 | 类型 | 示例 |
|------|------|------|
| 高 | 认证 | /login, /oauth/* |
| 高 | 数据 | /api/*/list, /search |
| 中 | 用户 | /users, /profile |
| 极高 | 管理 | /admin, /manage |

## 输出格式

\`\`\`
## 端点发现报告

- 总数: {count}
- 高风险: {high}
- 中风险: {medium}
- 低风险: {low}

### 高风险端点
1. {method} {path} - {reason}
\`\`\`
`;

const VULN_VERIFIER_PROMPT = `你是**漏洞验证专家**，专注于验证和确认安全漏洞。

## 职责

1. **快速验证** - 确认漏洞是否存在
2. **风险评估** - 判断实际影响
3. **PoC 生成** - 提供可执行的证明

## 验证流程

1. 构造 payload
2. 发送测试请求
3. 分析响应
4. 判断结果
5. 生成 PoC

## 输出格式

\`\`\`
## 验证结果

**漏洞类型**: {type}
**端点**: {endpoint}
**验证状态**: CONFIRMED / INVALID / UNCERTAIN
**严重程度**: Critical / High / Medium / Low / Info

### 测试步骤
1. {step}

### PoC
\`\`\`bash
{command}
\`\`\`

### 修复建议
{fix}
\`\`\`
`;

export function createApiSecurityAgent(
  name: string,
  description: string,
  prompt: string,
  mode: "primary" | "subagent" = "subagent",
  color?: string
): AgentConfig {
  return {
    description,
    mode,
    prompt,
    color,
    permission: {
      bash: "*",
      edit: "ask",
      webfetch: "allow",
    },
  };
}

const ApiSecurityTestingPlugin: Plugin = async (ctx) => {
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
          evidence: tool.schema.string().optional(),
        },
        async execute(args, ctx) {
          const deps = checkDeps(ctx);
          const corePath = getCorePath(ctx);
          const cmd = `${deps}python3 -c "
import sys
sys.path.insert(0, '${corePath}')
from verifiers.vuln_verifier import VulnVerifier
verifier = VulnVerifier()
result = verifier.verify('${args.vuln_type}', '${args.endpoint}', '${args.evidence or ''}')
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
          wait_for: tool.schema.string().optional(),
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
for ep in endpoints:
    print(ep)
"`;
          const result = await ctx.$`${cmd}`;
          return result.toString();
        },
      }),

      graphql_test: tool({
        description: "GraphQL 安全测试。参数: endpoint(GraphQL端点)",
        args: {
          endpoint: tool.schema.string(),
          introspection: tool.schema.boolean().optional(),
        },
        async execute(args, ctx) {
          const deps = checkDeps(ctx);
          const corePath = getCorePath(ctx);
          const cmd = `${deps}python3 -c "
import sys
sys.path.insert(0, '${corePath}')
from smart_analyzer import SmartAnalyzer
analyzer = SmartAnalyzer()
result = analyzer.graphql_test('${args.endpoint}', introspection=${args.introspection ?? true})
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
          target_user_id: tool.schema.string().optional(),
        },
        async execute(args, ctx) {
          const deps = checkDeps(ctx);
          const corePath = getCorePath(ctx);
          const cmd = `${deps}python3 -c "
import sys
sys.path.insert(0, '${corePath}')
from testers.idor_tester import IDORTester
tester = IDORTester()
result = tester.test('${args.endpoint}', '${args.resource_id}', '${args.target_user_id or ''}')
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
      const agentConfig = config.agent as Record<string, AgentConfig> | undefined;
      
      if (!agentConfig) {
        config.agent = {};
      }

      (config.agent as Record<string, AgentConfig>)["api-cyber-supervisor"] = createApiSecurityAgent(
        "api-cyber-supervisor",
        "API安全测试编排者。协调完整扫描流程，永不停止。",
        CYBER_SUPERVISOR_PROMPT,
        "primary",
        "#FF6B6B"
      );

      (config.agent as Record<string, AgentConfig>)["api-probing-miner"] = createApiSecurityAgent(
        "api-probing-miner",
        "漏洞挖掘专家。专注发现和验证 API 漏洞。",
        PROBING_MINER_PROMPT,
        "subagent"
      );

      (config.agent as Record<string, AgentConfig>)["api-resource-specialist"] = createApiSecurityAgent(
        "api-resource-specialist",
        "资源探测专家。专注采集和发现 API 端点。",
        RESOURCE_SPECIALIST_PROMPT,
        "subagent"
      );

      (config.agent as Record<string, AgentConfig>)["api-vuln-verifier"] = createApiSecurityAgent(
        "api-vuln-verifier",
        "漏洞验证专家。验证和确认安全漏洞。",
        VULN_VERIFIER_PROMPT,
        "subagent"
      );
    },
  };
};

export default ApiSecurityTestingPlugin;
