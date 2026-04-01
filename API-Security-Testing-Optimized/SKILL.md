# API 安全测试

针对授权目标进行结构化的 REST/GraphQL API 安全评估。

## 适用场景

- 审查 API 设计和实现的安全性
- 构建优先化的 API 安全测试矩阵
- 验证问题并提供清晰的证据
- 生成标准化的安全报告

## 安全边界

- **仅测试用户授权的目标**
- 默认使用非破坏性分析和低风险验证
- 不推荐破坏性、容量性或持久性操作
- 若范围、凭证或环境不清晰，明确声明假设并以最安全的方式继续

## 工作流程

### 1. 确认输入和评估模式

识别用户提供的内容：
- 目标 URL 或 base URL
- OpenAPI / Swagger 规范
- Postman 集合
- GraphQL schema 或自省输出
- 认证方式
- 测试账号或角色
- 环境限制
- 是否允许主动验证

选择评估模式：
- **文档驱动审查**：只有规范、集合、schema 可用
- **被动目标审查**：存在活动目标，但凭证或主动测试受限
- **授权主动评估**：用户提供足够的授权和上下文进行验证

参考：`references/intake.md`

### 2. 构建资产摘要

将 API 表面积映射为紧凑的清单：
- base URLs
- endpoints 或 operations
- 认证边界
- 角色和信任边界
- 敏感对象
- admin 或 internal 操作
- bulk、export、import、file、callback、search、mutation 流程
- 高价值工作流（用户管理、计费、token、secrets、审批、数据导出）

当表面积较大时，优先简洁覆盖而非穷举。

参考：`references/asset-discovery.md`

### 3. 构建优先化测试矩阵

创建覆盖以下内容的实用矩阵：
- 认证
- 授权
- 对象级访问
- 功能级访问
- 输入处理
- 敏感数据暴露
- 业务流滥用
- 速率限制
- 文档和调试暴露

根据 API 类型调整矩阵：
- REST API 使用 `references/rest-guidance.md`
- GraphQL API 使用 `references/graphql-guidance.md`

矩阵应解释：测试什么、为什么重要、多紧急。

参考：`references/test-matrix.md`

### 4. 验证和分类发现

仅在有足够支持时报告发现，包括：
- 受影响资产
- 证据
- 复现路径
- 现实影响
- 置信级别

证据不完整时：
- 标记为假设、弱信号或可能问题
- 明确解释确认所需内容

不要仅从模糊行为夸大严重性。

参考：`references/validation.md`

### 5. 生成最终报告

始终使用 `references/report-template.md` 中的报告模板。

每份报告必须包含：
- Scope（范围）
- Authorization assumptions（授权假设）
- Asset summary（资产摘要）
- Test matrix（测试矩阵）
- Findings（发现）
- Coverage gaps（覆盖缺口）
- Overall risk summary（总体风险摘要）

每个发现必须包含：
- Severity（严重性）
- Confidence（置信度）
- Affected asset（受影响资产）
- Description（描述）
- Evidence（证据）
- Reproduction（复现）
- Impact（影响）
- Remediation（修复）
- Retest notes（复测笔记）

## 严重性校准

使用一致的严重性语言：
- critical
- high
- medium
- low
- informational

证据不确定时，倾向保守校准。

## 协议处理

### REST APIs

关注：
- 资源暴露、method 处理、对象引用
- admin 功能、bulk 操作、export/import
- 错误处理和调试元数据

参考：`references/rest-guidance.md`

### GraphQL APIs

关注：
- 字段级授权、嵌套遍历、resolver 边界
- mutation 滥用、自省暴露、数据过度获取

参考：`references/graphql-guidance.md`

## 可选脚本

仅在脚本能减少脆弱的手动工作时使用：
- `scripts/normalize_openapi.py`
- `scripts/extract_endpoints.py`
- `scripts/render_report.py`

不要将内部引擎细节写入报告，除非用户明确要求。
