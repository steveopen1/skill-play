# Intelligent API Discovery - Technical Design

Feature Name: intelligent-api-discovery
Updated: 2026-04-01

## Description

本设计文档定义了真正由 AI 驱动的智能 API 发现机制的核心架构和组件。与传统基于硬编码正则的扫描器不同，这个系统以 LLM 作为核心决策者，实现真正的自主推理和动态适应。

**核心设计原则**：
1. **Agent 中心化**: LLM 是决策核心，不是辅助工具
2. **无硬编码**: 所有策略由 Agent 实时生成
3. **上下文驱动**: 每个决策都基于当前上下文
4. **持续学习**: Agent 在执行中不断更新自己的理解

## Architecture

```mermaid
graph TB
    subgraph "Agent Core"
        A["Agent Brain<br/>(LLM Decision Engine)"]
        C["Context Manager<br/>(动态上下文)"]
        L["Learning Engine<br/>(持续学习)"]
    end
    
    subgraph "Collectors (信息收集)"
        B["Browser Collector<br/>(动态交互)"]
        R["Response Analyzer<br/>(响应分析)"]
        S["Source Analyzer<br/>(全资源分析)"]
    end
    
    subgraph "Execution
        I["Insight Generator<br/>(洞察生成)"]
        P["Strategy Generator<br/>(策略生成)"]
        V["Validator<br/>(验证器)"]
    end
    
    A --> C
    A --> P
    A --> I
    
    C --> B
    C --> R
    C --> S
    
    L --> A
    
    B --> R
    R --> S
    S --> I
    I --> A
    
    P --> V
    V --> A
```

### 核心流程

```
1. 初始化 → Agent 分析目标，建立初始上下文
2. 观察 → Collector 收集信息（Browser/Sources/Responses）
3. 推理 → Agent 从观察中生成洞察
4. 策略 → Agent 基于洞察生成新的发现策略
5. 执行 → Agent 执行策略，触发更多观察
6. 学习 → Agent 更新上下文，重复 2-5 直到收敛
```

## Components

### 1. Agent Brain (LLM Decision Engine)

**职责**: 作为核心决策者，自主决定发现策略

**接口**:
```python
class AgentBrain:
    def analyze(self, context: Context, observations: List[Observation]) -> List[Insight]
    def generate_strategy(self, context: Context, insights: List[Insight]) -> Strategy
    def decide_next_action(self, context: Context) -> Action
    def learn(self, context: Context, result: Result) -> Context
```

**设计原则**:
- 不使用任何预定义的策略库
- 所有策略通过 LLM 实时生成
- 决策基于当前完整上下文

### 2. Context Manager

**职责**: 维护和更新发现上下文

**数据结构**:
```python
@dataclass
class DiscoveryContext:
    target: str
    tech_stack: TechStack
    discovered_endpoints: List[Endpoint]
    known_patterns: List[Pattern]
    api_base: Optional[str]
    auth_info: AuthInfo
    internal_ips: List[str]
    micro_services: List[Service]
    confidence_scores: Dict[str, float]
    exploration_history: List[Action]
```

**设计原则**:
- 上下文是动态的，持续更新
- 记录置信度而非仅记录发现
- 保留探索历史用于学习

### 3. Browser Collector (动态交互引擎)

**职责**: 自主控制浏览器，触发和监控 API 调用

**接口**:
```python
class BrowserCollector:
    async def explore(self, context: Context) -> List[NetworkRequest]
    async def interact(self, element: Element, action: Action) -> InteractionResult
    async def trigger_api(self, trigger: Trigger) -> APIRequest
```

**Agent 控制流程**:
```
Agent: "我发现了一个登录表单，需要填写并提交"
Browser: [填写表单] → [提交] → [捕获请求] → [返回给 Agent]
Agent: "请求成功，现在需要检查返回的用户菜单，发现更多 API"
...
```

**设计原则**:
- Browser 受 Agent 控制，不是自动化脚本
- 每个交互都是 Agent 的有意识决策
- 监控所有流量，包括 WebSocket

### 4. Source Analyzer (全资源分析)

**职责**: 分析所有类型的资源内容，提取 API 线索

**接口**:
```python
class SourceAnalyzer:
    def analyze_js(self, content: str, context: Context) -> AnalysisResult
    def analyze_css(self, content: str, context: Context) -> AnalysisResult
    def analyze_html(self, content: str, context: Context) -> AnalysisResult
    def analyze_response(self, response: Response, context: Context) -> AnalysisResult
```

**LLM 驱动的分析**（区别于正则）:
```python
# 传统方式（硬编码）
pattern = r'["\']\/api\/[a-zA-Z0-9_-]+["\']'
matches = re.findall(pattern, js_content)

# LLM 方式（智能理解）
prompt = f"""
分析以下 JavaScript 代码，找出所有 API 调用和端点。
不只是找字符串字面量，还要理解：
1. 动态构建的 URL
2. 环境变量中的 API 地址
3. 通过函数调用间接访问的 API
4. 条件分支中的 API

代码片段：
{js_content[:2000]}
"""
```

### 5. Response Analyzer (响应推导引擎)

**职责**: 从 API 响应内容推导出更多端点

**接口**:
```python
class ResponseAnalyzer:
    def infer_endpoints(self, response: Response, context: Context) -> List[InferredEndpoint]
    def analyze_schema(self, schema: dict, context: Context) -> List[Endpoint]
    def parse_hateoas(self, response: Response) -> List[Link]
```

**推导策略**:
1. **分页推导**: `{data: [...], page: 1, total: 100}` → `/api/xxx?page=2`
2. **嵌套资源**: `{user: {profile: {...}}}` → `/api/users/{id}/profile`
3. **CRUD 模式**: 发现 `GET /api/users` → 推导 `POST/PUT/DELETE /api/users`
4. **HATEOAS**: 解析 `Link` 头或响应中的 `_links` 字段

### 6. Learning Engine (持续学习)

**职责**: 从发现过程中学习，优化后续决策

**机制**:
```python
class LearningEngine:
    def record_decision(self, context: Context, action: Action, result: Result)
    def extract_pattern(self, decisions: List[Decision]) -> Pattern
    def update_confidence(self, pattern: Pattern, success: bool)
```

## Execution Modes

### 模式 1: 完全自主发现

```
User: "对这个 API 进行安全测试"
Agent: [启动发现流程]
  ├── 分析目标类型
  ├── 探索初始页面
  ├── 理解页面结构
  ├── 自主交互触发 API
  ├── 分析响应推导更多端点
  ├── 持续学习优化策略
  └── 收敛时输出完整端点列表
```

### 模式 2: 用户辅助发现

```
Agent: "我发现了一个不确定的登录流程，请帮我确认"
User: "这个按钮是提交工单的"
Agent: [更新上下文] → [触发工单相关 API]
...
```

### 模式 3: 增量发现

```
Agent: "已发现 15 个端点，发现速度在下降"
Agent: [调整策略] → [尝试不同的交互方式]
Agent: [发现新区域] → [成功扩展到 32 个端点]
```

## Context Understanding

### 启动时探查

```python
async def initial_probe(target: str) -> TechStack:
    # 1. 获取 HTML，分析页面类型
    html = await fetch(target)
    
    # 2. 检查 Server/Cookie 头，推断后端框架
    headers = await fetch_headers(target)
    
    # 3. 分析 JS 框架指纹
    js_fingerprints = await analyze_js_fingerprints(target)
    
    # 4. 检查 API 文档暴露
    doc_endpoints = await check_api_docs(target)
    
    return TechStack(
        frontend=infer_frontend(html),
        backend=infer_backend(headers),
        framework=infer_framework(js_fingerprints),
        has_api_docs=bool(doc_endpoints)
    )
```

### 运行时动态学习

```
WHEN Agent 发现新的 URL 模式
THEN Agent SHALL:
  1. 记录模式到上下文
  2. 生成类似的候选 URL
  3. 验证候选 URL
  4. 根据结果更新置信度

EXAMPLE:
- 发现: GET /api/v1/users/123
- 模式: /api/{version}/{resource}/{id}
- 推导: GET /api/v1/orders, POST /api/v1/users, DELETE /api/v1/products/456
- 验证: 逐个测试，更新置信度
```

## Integration with Skill Framework

### Skill 作为参考框架

```markdown
# SKILL.md (参考框架)

## Phase 1: 探索 (Exploration)
[框架指导，不是脚本]
- 理解目标结构
- 识别交互点
- 触发发现

## Phase 2: 分析 (Analysis)  
[框架指导，不是规则]
- LLM 理解资源内容
- 从响应推导端点
- 识别模式和关系

## Phase 3: 验证 (Validation)
[框架指导，不是列表]
- 验证端点可达性
- 确认请求方法
- 记录认证要求

## Phase 4: 扩展 (Expansion)
[框架指导，不是 fuzzing]
- 基于已知推导未知
- 探索边界情况
- 持续优化
```

### 脚本作为工具

```python
# scripts/browser_driver.py (工具，非决策者)
class BrowserDriver:
    """提供浏览器控制能力，由 Agent 决策如何使用"""
    
    def goto(self, url: str): ...
    def click(self, selector: str): ...
    def type(self, selector: str, text: str): ...
    def intercept_request(self, pattern: str): ...
    # ... 提供原子操作，不做业务决策

# scripts/response_parser.py (工具，非推理者)
class ResponseParser:
    """提供响应解析能力，由 Agent 决定解析什么"""
    
    def parse_json(self, response) -> dict: ...
    def extract_links(self, response) -> List[str]: ...
    def infer_schema(self, data) -> dict: ...
    # ... 提供基础能力，LLM 决定如何组合
```

## Error Handling

### Agent 遇到障碍

```python
IF Agent 遇到:
  - 401/403 (认证要求) → 评估是否需要认证，尝试获取或跳过
  - 429 (限速) → 降低请求频率，重新评估策略
  - WAF 拦截 → 改变请求特征，尝试绕过
  - 500 错误 → 分析错误信息，获取线索
  - 无响应 → 可能是内网地址，记录并继续探索其他路径
  
THEN Agent SHALL 自主决定如何应对
```

## Correctness Properties

1. **完整性**: Agent 尝试多种方法确保发现所有可达端点
2. **准确性**: 每个发现都有置信度，Agent 验证高价值目标
3. **效率**: Agent 根据上下文优先级选择探索路径
4. **自适应**: Agent 能处理任何类型的 Web 应用
5. **可解释**: Agent 的每个决策都有推理过程

## Test Strategy

### 单元测试

```python
def test_context_manager_update():
    ctx = DiscoveryContext(target="http://example.com")
    new_endpoint = Endpoint(path="/api/users", method="GET")
    updated_ctx = ctx.add_endpoint(new_endpoint)
    assert len(updated_ctx.discovered_endpoints) == 1

def test_response_analyzer_pagination():
    response = {"data": [], "page": 1, "total_pages": 10}
    analyzer = ResponseAnalyzer()
    inferred = analyzer.infer_pagination_urls(response, "/api/users")
    assert len(inferred) == 9  # page 2-10
```

### 集成测试

```python
async def test_agent_discovers_api():
    """测试 Agent 在真实 SPA 上发现端点"""
    # 使用测试靶场，如 Juice Shop, WebGoat
    agent = AgentBrain()
    context = await agent.initialize("http://test-target")
    
    while not context.converged():
        observations = await collect(context)
        insights = agent.analyze(context, observations)
        strategy = agent.generate_strategy(context, insights)
        await agent.execute(strategy, context)
    
    assert len(context.discovered_endpoints) > 10
```

### 对比测试

```python
def test_vs_hardcoded_scanner():
    """对比 LLM 驱动 vs 硬编码扫描器的发现率"""
    targets = ["spa-app", "mpa-app", "micro-services"]
    
    llm_results = run_intelligent_discovery(targets)
    hardcoded_results = run_hardcoded_scanner(targets)
    
    # LLM 应该发现 >= 硬编码扫描器的端点
    assert llm_results.total >= hardcoded_results.total
    # LLM 应该发现一些硬编码扫描器遗漏的端点
    assert len(llm_results.unique - hardcoded_results.unique) > 0
```

## Implementation Notes

### Phase 1: 核心架构

1. 实现 `AgentBrain` 的基本决策循环
2. 实现 `ContextManager` 的上下文维护
3. 实现基础的 `BrowserCollector`

### Phase 2: 分析能力

4. 实现 `SourceAnalyzer` 的 LLM 驱动分析
5. 实现 `ResponseAnalyzer` 的端点推导
6. 实现 `LearningEngine` 的模式学习

### Phase 3: 优化完善

7. 实现自适应策略调整
8. 实现用户辅助模式
9. 实现增量发现模式

## References

- EARS Syntax: https://earscount.com/ears-syntax/
- INCOSE Requirements: https://www.incose.org/
- LLM Agent Patterns: https://github.com/your-org/llm-agent-patterns
