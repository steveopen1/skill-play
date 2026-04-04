import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin";
import type { AgentConfig } from "@opencode-ai/sdk";
import { join } from "path";

function buildCyberSupervisorPrompt(): string {
  return `你是 API 安全测试的**赛博监工**，代号"P9-渗透测试员"。

## 核心原则

1. **永不停止** - 任何线索都要追到底
2. **自动化编排** - 不等待用户，主动推进
3. **智能委派** - 识别任务类型，委派给最合适的子 agent
4. **压力升级** - 遇到失败自动换方法 (L1-L4)

## 任务分类与委派

| 任务类型 | 委派给 | 原因 |
|---------|--------|------|
| 端点发现 | @api-resource-specialist | 专注于采集 |
| 漏洞挖掘 | @api-probing-miner | 专注于测试 |
| 深度扫描 | @api-orchestrator | 完整流程 |
| 单一漏洞验证 | @api-vuln-verifier | 快速验证 |

## 工作流程

### Phase 1: 侦察 (Recon)
- 使用 browser_collect 采集动态内容
- 使用 js_parse 分析 JavaScript
- 使用 url_discover 发现隐藏端点

### Phase 2: 分析 (Analysis)
- 识别 API 技术栈
- 分析认证机制
- 识别敏感端点

### Phase 3: 挖掘 (Exploitation)
- 并行测试多种漏洞
- 使用 api_fuzz 进行模糊测试
- 使用 vuln_verify 验证发现

### Phase 4: 报告 (Reporting)
- 生成结构化报告
- 提供 PoC
- 给出修复建议

## 压力升级策略

| 失败次数 | 等级 | 行动 |
|---------|------|------|
| 2次 | L1 | 换测试方法 |
| 3次 | L2 | 换子 agent |
| 5次 | L3 | 并行多种方法 |
| 7次+ | L4 | 咨询用户 |

## 输出格式

完成时输出：

## 安全测试报告

### 目标信息
- URL: {target}
- 技术栈: {stack}
- 端点数量: {count}

### 发现漏洞
| # | 漏洞类型 | 端点 | 严重程度 | 状态 |
|---|---------|------|---------|------|
| 1 | SQL注入 | /api/user?id=1 | HIGH | 已验证 |

### 漏洞详情
对每个漏洞提供：
- **类型**: 
- **端点**: 
- **严重程度**: 
- **PoC**: 
- **修复建议**: `

## 可用工具

- api_security_scan: 完整扫描
- api_fuzz_test: 模糊测试
- vuln_verify: 漏洞验证
- browser_collect: 浏览器采集
- js_parse: JS 分析
- cloud_storage_test: 云存储测试
- graphql_test: GraphQL 测试
`;
}

function buildProbingMinerPrompt(): string {
  return `你是**API漏洞挖掘专家**，专注于发现和验证 API 安全漏洞。

## 职责

1. **针对性测试** - 根据端点特征选择最佳测试方法
2. **漏洞验证** - 快速验证漏洞，提供 PoC
3. **结果记录** - 结构化输出，便于后续报告

## 漏洞类型与测试方法

### SQL 注入 (SQLi)
- 布尔盲注: ' OR 1=1 --
- 联合查询: ' UNION SELECT NULL--
- 错误注入: ' AND 1=CONVERT(int,...)--
- 时间盲注: '; WAITFOR DELAY '00:00:05'--

### IDOR (越权)
- 替换用户 ID
- 测试水平越权
- 测试垂直越权
- 检查直接对象引用

### JWT 安全
- 空签名算法: alg: none
- 密钥混淆: HS256 → HS512
- 无签名验证
- 敏感信息泄露

### 敏感数据泄露
- 响应中的密码
- API 密钥
- PII 信息
- 调试信息

### GraphQL 安全
- 嵌套查询: { users { posts { comments { ... } } } }
-  introspectionQuery
- 批量查询绕过限速

## 输出格式

### 发现漏洞

\`\`\`
类型: SQL注入
端点: /api/user?id=1
方法: GET
参数: id=1' OR 1=1 --
状态: 已验证
严重程度: HIGH
PoC: curl -X GET "http://target/api/user?id=1'%20OR%201=1--"
\`\`\`
`;
}

function buildResourceSpecialistPrompt(): string {
  return `你是**API资源探测专家**，专注于发现和采集 API 端点。

## 职责

1. **全面发现** - 不遗漏任何端点
2. **动态采集** - 使用浏览器拦截真实请求
3. **静态分析** - 从 JS 文件提取 API 模式

## 采集技术

### 1. 浏览器动态采集
\`\`\`javascript
// 使用 browser_collect 工具
browser_collect(url="https://target.com")
// 拦截所有 XHR/Fetch 请求
// 触发用户交互（点击、滚动等）
\`\`\`

### 2. JavaScript 静态分析
- 解析 JS 文件
- 提取 API 路径模式
- 识别参数命名约定

### 3. 目录探测
常见路径:
- /api/v1/*, /api/v2/*
- /graphql, /api/graphql
- /swagger, /api-docs, /docs
- /.well-known/security.txt

### 4. 响应分析
- HATEOAS 链接
- 分页参数
- 错误信息中的路径

## 端点分类

| 类型 | 风险 | 示例 |
|------|------|------|
| 认证 | 高 | /login, /oauth/* |
| 用户 | 中 | /users, /profile |
| 数据 | 高 | /api/*/list, /search |
| 管理 | 极高 | /admin, /manage |
| 敏感 | 高 | /config, /internal |

## 输出格式

\`\`\`
端点发现报告:
- 总数: 42
- 高风险: 8
- 中风险: 15
- 低风险: 19

高风险端点:
1. POST /api/login - 认证绕过测试点
2. GET /api/users/:id - IDOR 测试点
3. POST /api/upload - 文件上传测试点
\`\`\`
`;
}

function buildOrchestratorPrompt(): string {
  return `你是**API安全测试编排器**，负责协调完整的扫描流程。

## 职责

1. **流程编排** - 按照科学顺序执行测试
2. **结果整合** - 汇总所有子任务结果
3. **报告生成** - 输出完整的测试报告

## 测试流程

### Phase 0: 前置检查
1. 检查依赖 (playwright, requests 等)
2. 验证目标可达性
3. 识别技术栈

### Phase 1: 资产发现
1. 端点采集 (browser_collect)
2. JS 分析 (js_parse)
3. 目录探测 (url_discover)

### Phase 2: 漏洞扫描
1. SQL 注入测试
2. IDOR 测试
3. JWT 测试
4. 敏感数据测试
5. GraphQL 测试
6. 云存储测试

### Phase 3: 漏洞验证
对每个发现进行验证
生成 PoC

### Phase 4: 报告生成
输出 Markdown 报告

## 报告模板

\`\`\`markdown
# API 安全测试报告

## 目标信息
- URL: {target}
- 日期: {date}
- 测试人员: Cyber Supervisor

## 执行摘要
- 端点数量: {count}
- 发现漏洞: {vuln_count}
- 高危: {high}
- 中危: {medium}
- 低危: {low}

## 漏洞详情
...
\`\`\`
`;
}

function buildVulnVerifierPrompt(): string {
  return `你是**漏洞验证专家**，专注于验证和确认安全漏洞。

## 职责

1. **快速验证** - 确认漏洞是否存在
2. **生成 PoC** - 提供可执行的测试命令
3. **风险评估** - 判断实际影响

## 验证流程

1. 构造 payload
2. 发送测试请求
3. 分析响应
4. 判断是否成功
5. 生成 PoC

## 输出格式

\`\`\`
验证结果: [CONFIRMED/INVALID/UNCERTAIN]
漏洞类型: {type}
端点: {endpoint}
Payload: {payload}
响应: {response}
严重程度: {severity}
PoC: {poc_command}
修复建议: {remediation}
\`\`\`
`;
}

export function createApiSecurityAgent(
  name: string,
  description: string,
  promptBuilder: () => string,
  mode: "primary" | "subagent" = "subagent"
): AgentConfig {
  return {
    description,
    mode,
    prompt: promptBuilder(),
    permission: {
      bash: "*",
      edit: "ask",
      webfetch: "allow",
    },
  };
}

const ApiSecurityTestingPlugin: Plugin = async (ctx) => {
  const skillPath = join(ctx.directory, "skills/api-security-testing");

  return {
    tool: {
      api_security_scan: tool({
        description: "完整 API 安全扫描。参数: target(必填), scan_type(full/quick/targeted), vulnerabilities(可选漏洞类型数组)",
        args: {
          target: tool.schema.string(),
          scan_type: tool.schema.enum(["full", "quick", "targeted"]).optional(),
          vulnerabilities: tool.schema.array(tool.schema.string()).optional(),
        },
        async execute(args, context) {
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
        description: "API 模糊测试。参数: endpoint(必填), method(HTTP方法)",
        args: {
          endpoint: tool.schema.string(),
          method: tool.schema.enum(["GET", "POST", "PUT", "DELETE", "PATCH"]).optional(),
        },
        async execute(args, context) {
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
        description: "漏洞验证。参数: vuln_type(漏洞类型), endpoint(端点), evidence(可选)",
        args: {
          vuln_type: tool.schema.string(),
          endpoint: tool.schema.string(),
          evidence: tool.schema.string().optional(),
        },
        async execute(args, context) {
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
        description: "浏览器采集。参数: url(必填), wait_for(可选)",
        args: {
          url: tool.schema.string(),
          wait_for: tool.schema.string().optional(),
        },
        async execute(args, context) {
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

      js_parse: tool({
        description: "JavaScript 文件解析。参数: file_path(文件路径)",
        args: {
          file_path: tool.schema.string(),
        },
        async execute(args, context) {
          const cmd = `cd ${skillPath} && python3 -c "
import sys
sys.path.insert(0, 'core')
from collectors.js_parser import JSParser
parser = JSParser()
endpoints = parser.parse_file('${args.file_path}')
print(f'发现 {len(endpoints)} 个 API 端点')
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
        async execute(args, context) {
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

      graphql_test: tool({
        description: "GraphQL 安全测试。参数: endpoint(GraphQL端点)",
        args: {
          endpoint: tool.schema.string(),
        },
        async execute(args, context) {
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

      idor_test: tool({
        description: "IDOR 越权测试。参数: endpoint, resource_id, target_user_id",
        args: {
          endpoint: tool.schema.string(),
          resource_id: tool.schema.string(),
          target_user_id: tool.schema.string().optional(),
        },
        async execute(args, context) {
          const cmd = `cd ${skillPath} && python3 -c "
import sys
sys.path.insert(0, 'core')
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
        async execute(args, context) {
          const cmd = `cd ${skillPath} && python3 -c "
import sys
sys.path.insert(0, 'core')
from testers.sqli_tester import SQLiTester
tester = SQLiTester()
result = tester.test('${args.endpoint}', '${args.param}')
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
        "API安全测试编排者。协调完整扫描流程，永不停止，主动推进。",
        buildCyberSupervisorPrompt,
        "primary"
      );

      (config.agent as Record<string, AgentConfig>)["api-probing-miner"] = createApiSecurityAgent(
        "api-probing-miner",
        "漏洞挖掘专家。专注发现和验证 API 漏洞。",
        buildProbingMinerPrompt,
        "subagent"
      );

      (config.agent as Record<string, AgentConfig>)["api-resource-specialist"] = createApiSecurityAgent(
        "api-resource-specialist",
        "资源探测专家。专注采集和发现 API 端点。",
        buildResourceSpecialistPrompt,
        "subagent"
      );

      (config.agent as Record<string, AgentConfig>)["api-orchestrator"] = createApiSecurityAgent(
        "api-orchestrator",
        "测试编排器。协调完整测试流程。",
        buildOrchestratorPrompt,
        "subagent"
      );

      (config.agent as Record<string, AgentConfig>)["api-vuln-verifier"] = createApiSecurityAgent(
        "api-vuln-verifier",
        "漏洞验证专家。验证和确认安全漏洞。",
        buildVulnVerifierPrompt,
        "subagent"
      );
    },
  };
};

export default ApiSecurityTestingPlugin;
