# Intelligent API Discovery - Requirements

## Introduction

本需求文档定义了一个真正由 AI 驱动的智能 API 发现机制。区别于传统依赖硬编码正则的扫描器，这个系统将 LLM 作为核心决策者，实现真正的自主推理和动态适应。

**核心理念**：
- Skill 作为框架和流程参考，而非执行脚本
- Agent 作为决策核心，自主决定发现策略
- 不依赖任何硬编码的正则表达式或固定流程
- 真正随机应变的自适应发现机制

## Glossary

- **Agent**: LLM 驱动的智能决策者，能够理解上下文、生成策略、执行动作
- **Collector**: 信息收集器，负责从各个渠道获取原始数据
- **Browser Agent**: 能够自主操控浏览器的 Agent，负责触发和监控 API 调用
- **Context**: 当前的发现上下文，包括已知端点、技术栈、架构模式等
- **Insight**: Agent 从观察中生成的洞察，用于指导后续发现策略

## Requirements

### REQ-001: Agent 自主推理引擎

**User Story**: AS [Security Tester], I want [Agent 能够自主推理发现策略], so that [无需硬编码规则即可发现 API]

#### Acceptance Criteria

1. WHEN Agent 接收目标 URL, THEN Agent SHALL 首先分析目标类型（SPA/MPA/传统页面/纯 API 服务）
2. WHEN Agent 分析 HTML 内容, THEN Agent SHALL 理解页面结构并识别可交互元素
3. WHEN Agent 理解页面结构, THEN Agent SHALL 自主决定下一步交互策略（点击/输入/滚动/等待）
4. WHEN Agent 观察到网络流量, THEN Agent SHALL 分析请求模式并推断更多端点
5. WHEN Agent 发现新的 API 响应, THEN Agent SHALL 从响应内容推导相关端点
6. WHILE Agent 持续运行, THEN Agent SHALL 动态更新上下文和学习新模式

### REQ-002: Browser Agent 动态交互

**User Story**: AS [Agent], I want [能够自主控制浏览器与页面交互], so that [触发各种行为来发现隐藏 API]

#### Acceptance Criteria

1. WHEN Agent 需要与页面交互, THEN Agent SHALL 自主识别页面上的交互元素（按钮、表单、链接等）
2. WHEN Agent 执行交互动作, THEN Agent SHALL 同时监控所有网络请求
3. WHEN Agent 点击按钮后, THEN Agent SHALL 分析触发的 API 请求并理解其模式
4. WHEN Agent 发现表单, THEN Agent SHALL 自主填写合理数据并提交触发 API
5. WHEN Agent 需要更多交互, THEN Agent SHALL 自主决定是否滚动、悬停或等待
6. IF Agent 发现分页或加载更多, THEN Agent SHALL 自动触发以发现更多端点

### REQ-003: 全资源智能分析

**User Story**: AS [Agent], I want [能够分析所有类型的资源内容], so that [不遗漏任何可能暴露 API 的信息]

#### Acceptance Criteria

1. WHEN Agent 获取 JS 文件, THEN Agent SHALL 使用 LLM 理解 JS 代码逻辑而非正则匹配
2. WHEN Agent 获取 CSS 文件, THEN Agent SHALL 检查是否有隐藏的 API 路径引用
3. WHEN Agent 分析 HTML, THEN Agent SHALL 理解语义结构识别动态加载点
4. WHEN Agent 发现 JSON 响应, THEN Agent SHALL 分析数据结构推断相关 API
5. WHEN Agent 发现 XML/GraphQL 响应, THEN Agent SHALL 理解其格式并推导端点
6. WHEN Agent 分析 WebSocket 消息, THEN Agent SHALL 理解通信协议推导服务端点

### REQ-004: 上下文感知与动态学习

**User Story**: AS [Agent], I want [能够理解并适应不同的目标环境], so that [即使是微服务架构也能完整发现]

#### Acceptance Criteria

1. WHEN Agent 启动扫描, THEN Agent SHALL 探查目标的技术栈（SPA 框架/后端框架/网关类型）
2. WHEN Agent 发现微服务标志, THEN Agent SHALL 识别服务间通信模式和 API 网关
3. WHILE Agent 发现内网地址, THEN Agent SHALL 尝试探测相关联的服务
4. WHEN Agent 遇到认证要求, THEN Agent SHALL 评估认证类型（JWT/Cookie/Session）并尝试获取
5. WHEN Agent 发现 API 版本模式, THEN Agent SHALL 推导其他版本（v1/v2/v3）
6. WHEN Agent 发现新的 URL 模式, THEN Agent SHALL 自主生成类似模式的候选 URL

### REQ-005: 响应内容推导

**User Story**: AS [Agent], I want [能够从 API 响应内容推导出更多端点], so that [通过已知端点的响应发现更多隐藏端点]

#### Acceptance Criteria

1. WHEN Agent 获取分页响应, THEN Agent SHALL 识别分页参数模式并推导分页端点
2. WHEN Agent 发现嵌套资源, THEN Agent SHALL 识别资源关系并推导嵌套端点
3. WHEN Agent 发现 CRUD 相关字段, THEN Agent SHALL 识别资源类型并推导完整 CRUD 端点
4. WHEN Agent 获取超媒体响应 (HATEOAS), THEN Agent SHALL 提取所有链接作为新端点
5. WHEN Agent 发现错误响应, THEN Agent SHALL 分析错误消息获取路径或参数线索
6. WHEN Agent 获取 Swagger/OpenAPI 响应, THEN Agent SHALL 解析完整 API 定义

### REQ-006: Skill 框架而非脚本

**User Story**: AS [Agent], I want [Skill 只作为参考框架], so that [真正执行由 Agent 自主决策]

#### Acceptance Criteria

1. WHEN Agent 使用本 Skill, THEN Skill SHALL 提供流程框架和最佳实践而非具体脚本
2. WHEN Agent 需要发现策略, THEN Agent SHALL 自主生成而非从预定义策略中选择
3. WHEN Agent 遇到新情况, THEN Agent SHALL 自主决定如何应对而非查找硬编码规则
4. WHEN Skill 提供参考示例, THEN 这些示例 SHALL 仅作为 Agent 的学习材料
5. WHEN Agent 执行发现, THEN Agent SHALL 记录决策过程用于后续优化

## Non-Functional Requirements

### NFR-001: 灵活性
Agent SHALL 能够处理任何类型的 Web 应用，包括但不限于：
- 传统多页面应用 (MPA)
- 单页面应用 (SPA)
- JAMstack 应用
- 纯 API 服务
- 微服务架构

### NFR-002: 自适应性
- Agent SHALL 在发现过程中持续学习
- Agent SHALL 根据上下文动态调整策略
- Agent SHALL 能够处理认证、限速、WAF 等障碍

### NFR-003: 完整性
- Agent SHALL 尝试多种发现方法确保覆盖
- Agent SHALL 验证发现的端点确实可访问
- Agent SHALL 记录发现过程的置信度

## Out of Scope

- 具体的漏洞测试（属于 Testing 阶段）
- 性能测试或负载测试
- 移动端 API 测试（除非通过响应式 Web 访问）
- 认证绕过（除非是测试的一部分）
