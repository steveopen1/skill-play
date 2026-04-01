# Intelligent API Discovery - Task List

## Implementation Phases

### Phase 1: 核心架构 (Core Architecture)

- [x] 1.1 创建项目目录结构 `intelligent_discovery/`
- [x] 1.2 实现 `AgentBrain` - LLM 决策引擎核心
- [x] 1.3 实现 `ContextManager` - 动态上下文管理
- [x] 1.4 实现基础数据结构 (Endpoint, Observation, Insight, Strategy 等)

### Phase 2: 信息收集器 (Collectors)

- [x] 2.1 实现 `BrowserCollector` - 动态交互引擎
- [x] 2.2 实现 `SourceAnalyzer` - 全资源分析 (JS/HTML/CSS)
- [x] 2.3 实现 `ResponseAnalyzer` - 响应推导引擎

### Phase 3: 学习与优化 (Learning & Optimization)

- [x] 3.1 实现 `LearningEngine` - 持续学习引擎
- [x] 3.2 实现 `InsightGenerator` - 洞察生成器
- [x] 3.3 实现 `StrategyGenerator` - 策略生成器

### Phase 4: 集成与协调 (Integration)

- [x] 4.1 实现 `DiscoveryOrchestrator` - 协调各组件
- [x] 4.2 更新 SKILL.md - 作为参考框架
- [x] 4.3 编写单元测试

### Phase 5: 完善与测试 (Polish & Testing)

- [ ] 5.1 集成测试
- [ ] 5.2 端到端测试
- [ ] 5.3 文档完善

---

## 详细任务描述

### Phase 1: 核心架构

#### 1.1 创建项目目录结构

创建 `scripts/intelligent_discovery/` 目录，包含：
- `__init__.py`
- `agent_brain.py` - Agent Brain 模块
- `context_manager.py` - Context Manager 模块
- `collectors/` - 收集器子目录
- `models.py` - 数据模型

#### 1.2 实现 AgentBrain

核心接口：
```python
class AgentBrain:
    async def initialize(self, target: str) -> DiscoveryContext
    def analyze(self, context: DiscoveryContext, observations: List[Observation]) -> List[Insight]
    def generate_strategy(self, context: DiscoveryContext, insights: List[Insight]) -> Strategy
    def decide_next_action(self, context: DiscoveryContext) -> Action
    async def execute_action(self, action: Action, context: DiscoveryContext) -> Observation
    def learn(self, context: DiscoveryContext, result: ExecutionResult) -> DiscoveryContext
```

关键设计：
- 不使用预定义策略库
- 所有决策通过 LLM 提示词生成
- 维护完整的决策历史

#### 1.3 实现 ContextManager

数据结构：
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
    page_structure: PageStructure
    network_requests: List[NetworkRequest]
```

关键方法：
- `add_endpoint()` - 添加发现的端点
- `update_tech_stack()` - 更新技术栈
- `record_pattern()` - 记录发现的模式
- `update_confidence()` - 更新置信度
- `add_network_request()` - 添加网络请求

#### 1.4 实现基础数据模型

```python
@dataclass
class Endpoint:
    path: str
    method: str
    source: str
    confidence: float
    auth_required: bool
    params: List[Param]

@dataclass  
class Observation:
    type: ObservationType
    content: Any
    source: str
    timestamp: datetime
    
@dataclass
class Insight:
    type: InsightType
    content: str
    confidence: float
    findings: List[Finding]
    
@dataclass
class Strategy:
    actions: List[Action]
    reasoning: str
    expected_outcome: str
```

### Phase 2: 信息收集器

#### 2.1 BrowserCollector

核心能力：
- `navigate(url)` - 导航到 URL
- `get_page_structure()` - 获取页面结构
- `identify_interactive_elements()` - 识别可交互元素
- `interact(element, action)` - 与元素交互
- `monitor_network()` - 监控网络请求
- `get_network_requests()` - 获取捕获的请求

#### 2.2 SourceAnalyzer

LLM 驱动的分析方法：
```python
def analyze_js(self, content: str, context: DiscoveryContext) -> AnalysisResult:
    prompt = f"""
    分析以下 JavaScript 代码，找出所有 API 调用和端点。
    {content[:3000]}
    """
    # 使用 LLM 分析，而非正则
```

#### 2.3 ResponseAnalyzer

推导策略：
- `infer_pagination()` - 分页推导
- `infer_nested_resources()` - 嵌套资源推导
- `infer_crud_patterns()` - CRUD 模式推导
- `parse_hateoas()` - HATEOAS 解析
- `analyze_swagger()` - Swagger/OpenAPI 解析

### Phase 3: 学习与优化

#### 3.1 LearningEngine

机制：
```python
def record_decision(self, context, action, result):
    # 记录决策到历史
    
def extract_pattern(self, decisions) -> Pattern:
    # 从历史中提取模式
    
def update_confidence(self, pattern, success):
    # 根据成功/失败更新置信度
```

#### 3.2 InsightGenerator

从观察生成洞察：
```python
def generate_insights(self, observations: List[Observation]) -> List[Insight]:
    # 使用 LLM 从观察中提取洞察
```

#### 3.3 StrategyGenerator

生成发现策略：
```python
def generate_strategy(self, context: DiscoveryContext, insights: List[Insight]) -> Strategy:
    # 使用 LLM 基于当前上下文和洞察生成策略
```

### Phase 4: 集成与协调

#### 4.1 DiscoveryOrchestrator

主协调器，实现核心循环：
```python
async def run(self, target: str):
    # 1. 初始化
    context = await self.agent.initialize(target)
    
    # 2. 主循环
    while not context.converged():
        # 观察
        observations = await self.collectors.collect(context)
        
        # 分析
        insights = self.agent.analyze(context, observations)
        
        # 策略
        strategy = self.agent.generate_strategy(context, insights)
        
        # 执行
        for action in strategy.actions:
            result = await self.agent.execute_action(action, context)
            observations.append(result)
        
        # 学习
        context = self.agent.learn(context, result)
    
    return context.discovered_endpoints
```

### Phase 5: 完善与测试

#### 5.1 单元测试

为每个核心模块编写单元测试：
- test_agent_brain.py
- test_context_manager.py
- test_browser_collector.py
- test_source_analyzer.py
- test_response_analyzer.py

#### 5.2 集成测试

测试完整流程。

#### 5.3 端到端测试

在真实目标上测试。
