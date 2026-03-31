# Agentic Reasoning Enhancement - 需求文档

## 简介

本需求文档定义了 API 安全测试 Skill 的三大核心增强方向：
1. 推理深度加强 - 从表面现象到深层因果理解
2. 策略动态调整 - 根据上下文自适应测试策略
3. 上下文感知增强 - 全方位感知测试环境与目标特征

## 术语表

| 术语 | 定义 |
|------|------|
| Agentic Analyzer | 智能分析器，负责观察、推理、决策 |
| Context Window | 上下文窗口，存储当前测试会话的全局状态 |
| Strategy Pool | 策略池，包含预定义测试策略的集合 |
| Insight | 洞察，从观察中提取的有价值信息 |
| Understanding Level | 理解层级，从 Surface 到 Strategic 的认知阶梯 |

## 需求

### 需求 1: 多层级推理引擎

**用户故事:** 作为安全测试 Agent，我需要对测试响应进行深层推理，不仅仅识别"是什么"，更要理解"为什么"和"意味着什么"，以便调整后续测试策略。

#### 验收标准

1. WHEN Agent 观察到多个相似响应时，Agent SHALL 执行模式识别并提取共性特征
2. WHEN Agent 识别到异常模式时，Agent SHALL 执行因果推理来确定异常原因
3. WHEN Agent 完成推理后，Agent SHALL 生成包含"观察-推理-影响-策略"的四段式洞察
4. WHEN 推理结果置信度低于阈值时，Agent SHALL 标记需要进一步验证
5. WHEN Agent 面对新场景时，Agent SHALL 能够从历史推理中学习并复用

#### EARS 规范

| 类型 | 语句 |
|------|------|
| 事件驱动 | WHEN Agent 收集到新的响应数据，THEN Agent SHALL 执行多层级推理分析 |
| 状态驱动 | WHILE 推理置信度低于 0.7，Agent SHALL 标记当前洞察为"待验证"并继续数据收集 |
| 不期望行为 | IF Agent 发现响应模式自相矛盾，THEN Agent SHALL 生成冲突警告并暂停测试 |

### 需求 2: 动态策略调整系统

**用户故事:** 作为安全测试 Agent，我需要根据测试进展和发现动态调整测试策略，而不是遵循固定流程，以提升测试效率和准确性。

#### 验收标准

1. WHEN Agent 发现 WAF 防护时，Agent SHALL 自动切换到 WAF 绕过模式并调整 payload
2. WHEN Agent 发现目标技术栈时，Agent SHALL 优先使用针对该技术栈的专项测试
3. WHEN Agent 发现高价值端点（如认证接口）时，Agent SHALL 增加该端点的测试深度
4. WHEN Agent 遭遇连续失败（超过 5 次）时，Agent SHALL 自动降低测试速率并记录封锁
5. WHEN Agent 完成一个测试阶段时，Agent SHALL 评估是否需要回退或深入特定领域
6. WHEN 测试进度超过预设时间时，Agent SHALL 基于已发现漏洞的重要性调整后续测试优先级

#### EARS 规范

| 类型 | 语句 |
|------|------|
| 事件驱动 | WHEN Agent 检测到 WAF 特征，THEN Agent SHALL 从策略池加载 WAF 绕过策略 |
| 事件驱动 | WHEN Agent 发现新的 API 端点，THEN Agent SHALL 重新评估端点优先级并调整测试队列 |
| 状态驱动 | WHILE 目标技术栈识别为 Spring，Agent SHALL 优先测试 Java 特有漏洞（如 SQL 注入点在 MyBatis） |
| 不期望行为 | IF 请求被封锁超过 3 次，THEN Agent SHALL 降低速率 50% 并记录封锁特征 |

### 需求 3: 全维度上下文感知

**用户故事:** 作为安全测试 Agent，我需要全面感知测试环境的上下文信息，包括技术栈、网络环境、防护机制、敏感度等级等，以做出更准确的测试决策。

#### 验收标准

1. WHEN Agent 开始测试时，Agent SHALL 自动识别目标技术栈（前端框架、后端语言、数据库）
2. WHEN Agent 发起请求时，Agent SHALL 维护请求上下文（来源端点、参数、历史调用链）
3. WHEN Agent 分析响应时，Agent SHALL 检测响应特征（SPA fallback、API 文档、错误泄露）
4. WHEN Agent 发现内网地址时，Agent SHALL 标记该地址并提示需要代理访问
5. WHEN Agent 处理敏感数据（如 JWT、API Key）时，Agent SHALL 自动启用安全模式
6. WHEN Agent 测试认证接口时，Agent SHALL 启用最小化原则避免账户锁定
7. WHEN Agent 收集到新情报时，Agent SHALL 更新全局上下文窗口并同步到所有模块

#### EARS 规范

| 类型 | 语句 |
|------|------|
| 事件驱动 | WHEN Agent 接收到 HTTP 响应，THEN Agent SHALL 提取技术栈指纹并更新上下文 |
| 事件驱动 | WHEN Agent 发现新的 API 路径，THEN Agent SHALL 分析该路径与已发现端点的关联关系 |
| 状态驱动 | WHILE 测试上下文包含内网地址，Agent SHALL 禁用直接连接并提示用户配置代理 |
| 状态驱动 | WHILE 测试目标包含敏感操作（支付/密码修改），Agent SHALL 启用最小化影响模式 |
| 不期望行为 | IF Agent 检测到敏感数据在未加密通道传输，THEN Agent SHALL 生成安全风险警告 |

### 需求 4: 洞察驱动的测试循环

**用户故事:** 作为安全测试 Agent，我需要建立"观察→推理→策略→执行→验证"的闭环测试循环，使测试过程能够自我改进。

#### 验收标准

1. WHEN Agent 生成新洞察时，Agent SHALL 将洞察纳入后续测试决策考量
2. WHEN Agent 执行测试后，Agent SHALL 验证测试结果是否符合预期
3. WHEN Agent 发现预期外的测试结果时，Agent SHALL 生成新假设并验证
4. WHEN Agent 完成测试会话时，Agent SHALL 生成测试有效性评估报告
5. WHEN Agent 发现测试策略失效时，Agent SHALL 记录该模式到策略黑名单

#### EARS 规范

| 类型 | 语句 |
|------|------|
| 事件驱动 | WHEN Agent 收到测试响应，THEN Agent SHALL 对比响应与预期并记录差异 |
| 事件驱动 | WHEN Agent 发现的漏洞数量为 0，THEN Agent SHALL 生成"假阴性风险"警告 |
| 状态驱动 | WHILE 测试循环未收敛（持续发现新问题），Agent SHALL 继续迭代直到达到最大深度 |

### 需求 5: 人机协作接口

**用户故事:** 作为测试操作者，我需要与 Agent 进行多轮交互，指导测试方向、确认发现、调整策略。

#### 验收标准

1. WHEN Agent 生成重要发现时，Agent SHALL 暂停测试并请求用户确认
2. WHEN 用户提出新测试目标时，Agent SHALL 将目标纳入当前测试上下文
3. WHEN 用户否决某个测试策略时，Agent SHALL 记录偏好并避免后续使用
4. WHEN Agent 完成测试阶段时，Agent SHALL 生成阶段性报告供用户审阅
5. WHEN 用户请求解释时，Agent SHALL 提供推理过程的完整说明

#### EARS 规范

| 类型 | 语句 |
|------|------|
| 事件驱动 | WHEN Agent 发现高危漏洞，THEN Agent SHALL 暂停测试并通知用户确认 |
| 事件驱动 | WHEN 用户修改测试目标，THEN Agent SHALL 重置上下文并重新制定测试计划 |
| 状态驱动 | WHILE 用户未确认测试策略，Agent SHALL 保持等待状态 |

## 成功标准

1. 推理引擎能够生成包含"观察-推理-影响-策略"四要素的洞察
2. 策略系统能够根据上下文自动切换至少 5 种不同策略
3. 上下文感知能够识别并跟踪至少 10 种不同的上下文维度
4. 测试循环能够基于洞察自动调整后续测试行为
5. 人机接口支持暂停、继续、修改目标、解释推理等交互

## 约束条件

1. 所有推理必须在可配置的时间阈值内完成（默认 5 秒）
2. 策略切换必须可追溯，支持审计
3. 上下文信息必须安全存储，不泄露敏感数据
4. 人机交互必须是异步的，不阻塞测试进度
