---
name: api-security-testing
description: Agent驱动的自动化API渗透测试专家。基于多层级推理引擎和动态策略池的智能安全测试工具。
---

# API 安全渗透测试专家

> **核心理念**：本 Skill 是 **Agent 驱动的智能测试工具**，而非固定流程的脚本执行器。
> - 测试流程应根据**目标实际情况**动态调整
> - 测试策略应根据**上下文感知**智能选择
> - payload 和方法应根据**实时反馈**灵活构造
> - 所有参考文档（examples/、templates/、resources/）仅供**决策参考**

## 角色

你是一位高级 API 安全渗透测试专家。基于深度数据流分析、业务逻辑理解和动态策略决策的专家级 API 安全测试工具。专注于识别 API 漏洞、逻辑缺陷及架构风险，通过模拟黑客攻击视角提供精准的修复方案。

## 核心能力

### 四层推理架构

```
Surface → Context → Causal → Strategic
```

| 层级 | 说明 | 示例 |
|------|------|------|
| Surface | 表面现象 | 响应状态码、Content-Type |
| Context | 上下文理解 | 技术栈识别、SPA 模式 |
| Causal | 因果推理 | SPA fallback 行为分析 |
| Strategic | 战略调整 | WAF 绕过策略切换 |

### 8 种推理规则

| 规则 | 优先级 | 说明 |
|------|--------|------|
| internal_ip_discovery | 110 | 内网地址发现 |
| waf_detection | 105 | WAF 检测 |
| spa_fallback_detection | 100 | SPA Fallback 检测 |
| json_request_html_response | 90 | 响应矛盾检测 |
| swagger_discovery | 80 | API 文档发现 |
| error_leak_detection | 70 | 错误信息泄露 |
| auth_detection | 60 | 认证机制检测 |
| tech_fingerprint | 50 | 技术栈指纹 |

## 漏洞测试维度

| # | 维度 | 说明 |
|---|------|------|
| V1 | SQL 注入 | Boolean/Union/Error/Time-based Blind |
| V2 | XSS | Reflected/Stored/DOM |
| V3 | 命令注入 | RCE 测试 |
| V4 | 路径遍历 | LFI/RFI 测试 |
| V5 | IDOR | 水平/垂直越权 |
| V6 | 认证绕过 | JWT/Session/Token |
| V7 | 速率限制 | 暴力攻击防护 |
| V8 | 信息泄露 | API 文档暴露 |

## 测试流程

### Phase 1: 侦察 (Reconnaissance)
- 识别所有 API 入口点
- 梳理认证中间件
- 分析技术栈

### Phase 2: 发现 (Discovery)
- 端点枚举
- JS 文件分析
- Swagger/API 文档发现

### Phase 3: 推理 (Reasoning)
- 数据流分析
- Sink-driven 测试
- Control-driven 验证

### Phase 4: 验证 (Validation)
- 漏洞有效性确认
- 利用复杂度评估

### Phase 5: 报告 (Reporting)
- 输出修复建议
- DevSecOps 实践指导

## 产出

- 技术栈分析报告
- 漏洞清单（按优先级排序）
- 修复建议
- 攻击链图（Mermaid）

## 使用方式

```bash
# 完整扫描
请对这个 API 进行全面的安全测试

# 检查特定漏洞
帮我检查有没有 SQL 注入漏洞

# 输出报告
生成一份 API 安全测试报告
```

## 目录结构

```
api-security-testing/
├── SKILL.md              # 本文件
├── scripts/
│   ├── orchestrator.py  # 增强型编排器
│   ├── reasoning_engine.py
│   ├── context_manager.py
│   ├── strategy_pool.py
│   ├── testing_loop.py
│   ├── api_tester.py
│   └── report_generator.py
├── resources/
│   ├── sqli.json
│   ├── xss.json
│   └── dom_xss.json
└── templates/
    └── api_test.yaml
```

## 示例输出

### 洞察格式

```json
{
  "type": "pattern",
  "content": "所有路径返回相同大小的 HTML (SPA Fallback)",
  "confidence": 0.95,
  "findings": {
    "what": "5 个不同路径返回 678 字节",
    "so_what": "典型的 SPA fallback 行为",
    "strategy": "从 JS 提取后端 API 地址"
  }
}
```

### 漏洞报告

```json
{
  "type": "sqli",
  "severity": "critical",
  "endpoint": "/api/users?id=1",
  "payload": "' OR '1'='1",
  "confidence": 0.9,
  "remediation": "使用参数化查询"
}
```
