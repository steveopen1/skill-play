"""
Intelligent API Discovery - Agent Brain

LLM 驱动的决策引擎，核心特点：
1. 不使用预定义策略库
2. 所有策略通过 LLM 实时生成
3. 决策基于当前完整上下文
"""

import json
import re
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from .models import (
    DiscoveryContext, Observation, Insight, Strategy, Action,
    ActionType, InsightType, Endpoint, NetworkRequest, Pattern,
    TechStack, TechStackType, Finding, ObservationType, PageStructure,
    ExecutionResult
)


LLM_PROMPTS = {
    "system_prompt": """你是一个专业的 API 安全测试专家，擅长智能发现 Web 应用中的 API 端点。

你的核心能力：
1. 理解页面结构和 JavaScript 代码，识别 API 调用模式
2. 分析网络请求，理解 API 的请求/响应格式
3. 从响应内容推导相关的 API 端点
4. 识别技术栈和认证机制

关键原则：
- 不依赖硬编码的正则表达式
- 通过真正理解代码逻辑来发现 API
- 考虑动态构建的 URL、环境变量、条件分支等
- 记录每个发现的置信度

你将与我协作完成 API 发现任务。""",

    "analyze_observation": """分析以下观察结果，生成洞察：

观察类型：{obs_type}
观察来源：{obs_source}
内容摘要：{content_summary}

已知上下文：
- 已发现 {endpoints_count} 个端点
- 技术栈：{tech_stack}
- API Base：{api_base}
- 已有模式：{patterns}

请生成洞察，要求：
1. 识别新发现的 API 端点或模式
2. 判断技术栈信息
3. 识别潜在的机会或障碍
4. 为后续发现策略提供建议

输出 JSON 格式：
{{
  "insights": [
    {{
      "type": "endpoint|pattern|tech_stack|opportunity|blocker",
      "content": "洞察内容描述",
      "confidence": 0.0-1.0,
      "findings": [
        {{
          "what": "发现了什么",
          "so_what": "这意味着什么",
          "evidence": ["证据1", "证据2"]
        }}
      ]
    }}
  ]
}}""",

    "generate_strategy": """基于以下洞察，生成下一步发现策略：

当前上下文：
- 目标：{target}
- 已发现端点：{endpoints}
- 技术栈：{tech_stack}
- API Base：{api_base}
- 探索历史：{history}

当前洞察：
{insights}

请生成发现策略，要求：
1. 选择最有可能发现新端点的动作
2. 考虑技术的覆盖度（JS分析、页面交互、响应推导等）
3. 给出每个动作的推理过程

可选动作类型：
- NAVIGATE: 导航到 URL
- CLICK: 点击元素
- TYPE: 输入文本
- SCROLL: 滚动页面
- FETCH_API: 直接调用 API
- ANALYZE_SOURCE: 分析源代码

输出 JSON 格式：
{{
  "reasoning": "策略推理过程",
  "expected_outcome": "期望的结果",
  "confidence": 0.0-1.0,
  "actions": [
    {{
      "type": "动作类型",
      "target": "目标元素或 URL",
      "params": {{}},
      "reasoning": "为什么执行这个动作"
    }}
  ]
}}""",

    "decide_next_action": """基于当前上下文，决定下一步动作：

当前上下文：
{context_summary}

最近的动作：{recent_actions}
已发现端点：{endpoints}

请决定下一步动作，输出 JSON 格式：
{{
  "action": {{
    "type": "动作类型",
    "target": "目标",
    "params": {{}},
    "reasoning": "为什么这样做"
  }},
  "priority": "high|medium|low"
}}""",

    "analyze_js": """分析以下 JavaScript 代码，找出所有 API 调用和端点。

不只是找字符串字面量，还要理解：
1. 动态构建的 URL（如 baseURL + path）
2. 环境变量或配置中的 API 地址
3. 通过函数调用间接访问的 API
4. 条件分支中的不同 API
5. WebSocket 连接
6. GraphQL 查询

代码片段：
{js_code}

输出 JSON 格式：
{{
  "endpoints": [
    {{
      "path": "/api/users",
      "method": "GET",
      "construction": "literal|dynamic|indirect",
      "confidence": 0.0-1.0,
      "reasoning": "如何发现这个端点"
    }}
  ],
  "api_bases": ["http://api.example.com"],
  "patterns": ["/api/{{resource}}/{{id}}"],
  "websocket_urls": ["wss://..."]
}}""",

    "analyze_response": """分析以下 API 响应，推导更多端点：

当前端点：{endpoint}
响应内容：{response}

请分析：
1. 分页信息（page, total, limit 等）
2. 嵌套资源关系（如 user.profile, order.items）
3. CRUD 模式（如果发现 GET，是否有 POST/PUT/DELETE）
4. HATEOAS 链接
5. 错误响应中的路径信息

输出 JSON 格式：
{{
  "inferred_endpoints": [
    {{
      "path": "/api/users/123/profile",
      "method": "GET",
      "confidence": 0.0-1.0,
      "reasoning": "如何推导"
    }}
  ],
  "pagination_pattern": "{{start}}-{{end}}",
  "nested_resources": ["user.profile", "order.items"],
  "hateoas_links": ["http://..."]
}}""",

    "understand_page_structure": """分析以下页面结构，识别可交互元素：

页面标题：{title}
URL：{url}

页面中的元素：
{elements}

请识别：
1. 表单元素（登录、搜索、提交等）
2. 按钮和链接
3. 导航元素
4. 可能触发 API 调用的交互点

输出 JSON 格式：
{{
  "interactive_elements": [
    {{
      "selector": "css选择器或xpath",
      "type": "button|input|link|form",
      "action": "click|type|submit",
      "description": "描述",
      "potential_api": "可能的 API 调用"
    }}
  ],
  "forms": [
    {{
      "selector": "form选择器",
      "fields": ["username", "password"],
      "submit_action": "触发的 API"
    }}
  ]
}}"""
}


class AgentBrain:
    """
    LLM 驱动的 API 发现决策引擎
    
    核心职责：
    1. 分析观察结果，生成洞察
    2. 基于洞察和上下文，生成发现策略
    3. 决定下一步具体动作
    4. 从执行结果中学习
    """
    
    def __init__(self, llm_client=None):
        """
        初始化 Agent Brain
        
        Args:
            llm_client: LLM 客户端，如 openai, anthropic 等。
                       如果为 None，则使用模拟的 LLM 用于测试
        """
        self.llm_client = llm_client
        self._history: List[Dict] = []
    
    async def initialize(self, target: str) -> DiscoveryContext:
        """
        初始化发现上下文
        
        Args:
            target: 目标 URL
            
        Returns:
            DiscoveryContext: 初始上下文
        """
        context = DiscoveryContext(target=target)
        
        if self.llm_client:
            context = await self._probe_target(context)
        
        return context
    
    async def _probe_target(self, context: DiscoveryContext) -> DiscoveryContext:
        """
        探查目标，初步了解技术栈
        
        这是一个默认实现，可以被重写或增强
        """
        return context
    
    def analyze(
        self,
        context: DiscoveryContext,
        observations: List[Observation]
    ) -> List[Insight]:
        """
        分析观察结果，生成洞察
        
        Args:
            context: 当前发现上下文
            observations: 新收集的观察结果
            
        Returns:
            List[Insight]: 生成的洞察列表
        """
        insights = []
        
        for obs in observations:
            if obs.type == ObservationType.NETWORK_REQUEST:
                insight = self._analyze_network_request(obs, context)
                if insight:
                    insights.append(insight)
            
            elif obs.type == ObservationType.PAGE_STRUCTURE:
                insight = self._analyze_page_structure(obs, context)
                if insight:
                    insights.append(insight)
        
        return insights
    
    def _analyze_network_request(
        self,
        obs: Observation,
        context: DiscoveryContext
    ) -> Optional[Insight]:
        """分析网络请求观察"""
        if not isinstance(obs.content, NetworkRequest):
            return None
        
        request: NetworkRequest = obs.content
        
        if not request.is_api:
            return None
        
        findings = []
        
        findings.append(Finding(
            what=f"发现 API 请求: {request.method} {request.url}",
            so_what="这是一个 API 端点，需要添加到端点列表",
            evidence=[f"响应状态: {request.response_status}"]
        ))
        
        if "jwt" in request.headers.get("authorization", "").lower():
            findings.append(Finding(
                what="检测到 JWT 认证",
                so_what="该 API 使用 JWT 进行认证",
                evidence=[request.headers.get("authorization", "")]
            ))
        
        endpoint = Endpoint(
            path=self._extract_path(request.url),
            method=request.method,
            source="network_capture",
            confidence=0.9
        )
        context.add_endpoint(endpoint)
        
        return Insight(
            type=InsightType.ENDPOINT,
            content=f"从网络流量中发现 API: {request.method} {request.url}",
            confidence=0.9,
            findings=findings
        )
    
    def _analyze_page_structure(
        self,
        obs: Observation,
        context: DiscoveryContext
    ) -> Optional[Insight]:
        """分析页面结构观察"""
        if not isinstance(obs.content, PageStructure):
            return None
        
        page: PageStructure = obs.content
        findings = []
        
        if page.forms:
            findings.append(Finding(
                what=f"发现 {len(page.forms)} 个表单",
                so_what="表单提交可能触发 API 调用",
                evidence=[str(f.get("fields", [])) for f in page.forms[:3]]
            ))
        
        if page.interactive_elements:
            findings.append(Finding(
                what=f"发现 {len(page.interactive_elements)} 个可交互元素",
                so_what="这些元素可能触发 API 调用",
                evidence=[str(e.get("type", "")) for e in page.interactive_elements[:5]]
            ))
        
        return Insight(
            type=InsightType.PATTERN,
            content=f"页面 {page.url} 包含可交互元素",
            confidence=0.7,
            findings=findings
        )
    
    def generate_strategy(
        self,
        context: DiscoveryContext,
        insights: List[Insight]
    ) -> Strategy:
        """
        基于洞察生成发现策略
        
        Args:
            context: 当前发现上下文
            insights: 当前的洞察列表
            
        Returns:
            Strategy: 生成的发现策略
        """
        if self.llm_client:
            return self._generate_strategy_with_llm(context, insights)
        else:
            return self._generate_strategy_fallback(context, insights)
    
    def _generate_strategy_with_llm(
        self,
        context: DiscoveryContext,
        insights: List[Insight]
    ) -> Strategy:
        """使用 LLM 生成策略"""
        prompt = LLM_PROMPTS["generate_strategy"].format(
            target=context.target,
            endpoints=self._summarize_endpoints(context.discovered_endpoints),
            tech_stack=context.tech_stack.to_dict(),
            api_base=context.api_base or "unknown",
            history=self._summarize_history(context.exploration_history),
            insights=self._summarize_insights(insights)
        )
        
        response = self._call_llm(prompt)
        
        try:
            data = json.loads(response)
            actions = []
            for a in data.get("actions", []):
                actions.append(Action(
                    type=ActionType(a["type"]),
                    target=a.get("target"),
                    params=a.get("params", {}),
                    reasoning=a.get("reasoning", "")
                ))
            
            return Strategy(
                actions=actions,
                reasoning=data.get("reasoning", ""),
                expected_outcome=data.get("expected_outcome", ""),
                confidence=data.get("confidence", 0.5)
            )
        except (json.JSONDecodeError, KeyError):
            return self._generate_strategy_fallback(context, insights)
    
    def _generate_strategy_fallback(
        self,
        context: DiscoveryContext,
        insights: List[Insight]
    ) -> Strategy:
        """
        回退策略生成（当没有 LLM 时使用启发式方法）
        
        这本身不是硬编码规则，而是 LLM 不可用时的默认行为
        """
        actions = []
        
        if not context.page_structures:
            actions.append(Action(
                type=ActionType.NAVIGATE,
                target=context.target,
                reasoning="初始探索：获取页面结构"
            ))
        elif len(context.exploration_history) < 3:
            for page in context.page_structures[-1:]:
                for form in page.forms[:2]:
                    actions.append(Action(
                        type=ActionType.TYPE,
                        target=form.get("selector"),
                        params={"text": "test"},
                        reasoning=f"测试表单: {form.get('selector')}"
                    ))
        
        for insight in insights:
            if insight.type == InsightType.OPPORTUNITY:
                if "js" in insight.content.lower():
                    actions.append(Action(
                        type=ActionType.ANALYZE_SOURCE,
                        target="current_page",
                        reasoning="分析页面 JS 文件"
                    ))
        
        if not actions:
            actions.append(Action(
                type=ActionType.SCROLL,
                target="current_page",
                params={"direction": "down"},
                reasoning="滚动页面以触发懒加载内容"
            ))
        
        return Strategy(
            actions=actions,
            reasoning="基于上下文的默认策略（LLM 不可用）",
            expected_outcome="继续探索发现更多端点",
            confidence=0.5
        )
    
    def decide_next_action(self, context: DiscoveryContext) -> Tuple[Action, str]:
        """
        决定下一步具体动作
        
        Args:
            context: 当前发现上下文
            
        Returns:
            Tuple[Action, priority]: 动作和优先级
        """
        if self.llm_client:
            prompt = LLM_PROMPTS["decide_next_action"].format(
                context_summary=self._summarize_context(context),
                recent_actions=self._summarize_history(context.exploration_history[-5:]),
                endpoints=self._summarize_endpoints(context.discovered_endpoints[:10])
            )
            
            response = self._call_llm(prompt)
            
            try:
                data = json.loads(response)
                action_data = data.get("action", {})
                action = Action(
                    type=ActionType(action_data.get("type", "WAIT")),
                    target=action_data.get("target"),
                    params=action_data.get("params", {}),
                    reasoning=action_data.get("reasoning", "")
                )
                return action, data.get("priority", "medium")
            except (json.JSONDecodeError, KeyError):
                pass
        
        return self._decide_action_fallback(context)
    
    def _decide_action_fallback(
        self,
        context: DiscoveryContext
    ) -> Tuple[Action, str]:
        """回退动作决策"""
        if not context.page_structures:
            return Action(
                type=ActionType.NAVIGATE,
                target=context.target,
                reasoning="获取初始页面"
            ), "high"
        
        last_page = context.page_structures[-1]
        
        if last_page.forms:
            form = last_page.forms[0]
            return Action(
                type=ActionType.TYPE,
                target=form.get("selector", "input[type='text']"),
                params={"text": "admin"},
                reasoning="测试表单输入"
            ), "high"
        
        if last_page.interactive_elements:
            element = last_page.interactive_elements[0]
            return Action(
                type=ActionType.CLICK,
                target=element.get("selector"),
                reasoning=f"点击元素: {element.get('description', '')}"
            ), "medium"
        
        return Action(
            type=ActionType.SCROLL,
            target="current_page",
            params={"direction": "down"},
            reasoning="滚动触发懒加载"
        ), "low"
    
    def learn(
        self,
        context: DiscoveryContext,
        result: 'ExecutionResult'
    ) -> DiscoveryContext:
        """
        从执行结果中学习，更新上下文
        
        Args:
            context: 当前上下文
            result: 执行结果
            
        Returns:
            DiscoveryContext: 更新后的上下文
        """
        self._history.append({
            "action": result.action.to_dict(),
            "success": result.success,
            "observations_count": len(result.observations),
            "timestamp": datetime.now().isoformat()
        })
        
        if result.success and result.observations:
            for obs in result.observations:
                if obs.type == ObservationType.NETWORK_REQUEST:
                    if isinstance(obs.content, NetworkRequest):
                        ep = Endpoint(
                            path=self._extract_path(obs.content.url),
                            method=obs.content.method,
                            source="learning",
                            confidence=0.8
                        )
                        context.add_endpoint(ep)
        
        return context
    
    def _extract_path(self, url: str) -> str:
        """从 URL 提取路径部分"""
        if not url:
            return ""
        
        if url.startswith("http"):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.path or "/"
        
        if url.startswith("/"):
            return url
        
        return "/" + url
    
    def _summarize_endpoints(self, endpoints: List[Endpoint]) -> str:
        """总结端点列表"""
        if not endpoints:
            return "暂无"
        
        summary = []
        for ep in endpoints[:10]:
            summary.append(f"  - {ep.method} {ep.path} (置信度: {ep.confidence:.2f})")
        
        if len(endpoints) > 10:
            summary.append(f"  ... 还有 {len(endpoints) - 10} 个")
        
        return "\n".join(summary)
    
    def _summarize_history(self, actions: List[Action]) -> str:
        """总结动作历史"""
        if not actions:
            return "暂无"
        
        summary = []
        for a in actions[-5:]:
            summary.append(f"  - {a.type.value}: {a.target}")
        
        return "\n".join(summary)
    
    def _summarize_insights(self, insights: List[Insight]) -> str:
        """总结洞察列表"""
        if not insights:
            return "暂无"
        
        summary = []
        for i in insights:
            summary.append(f"  - [{i.type.value}] {i.content[:50]}...")
        
        return "\n".join(summary)
    
    def _summarize_context(self, context: DiscoveryContext) -> str:
        """总结上下文"""
        return f"""目标: {context.target}
已发现端点: {len(context.discovered_endpoints)}
技术栈: {context.tech_stack.frontend.value} / {context.tech_stack.backend.value}
API Base: {context.api_base or '未知'}
探索次数: {len(context.exploration_history)}
网络请求: {len(context.network_requests)}
当前页面: {context.page_structures[-1].url if context.page_structures else '无'}"""
    
    def _call_llm(self, prompt: str) -> str:
        """
        调用 LLM（需要外部实现）
        
        这是一个抽象方法，子类或外部需要注入 LLM 客户端
        """
        if self.llm_client:
            return self.llm_client.generate(prompt)
        
        return "{}"
    
    def get_history(self) -> List[Dict]:
        """获取决策历史"""
        return self._history


def create_agent_brain(llm_client=None) -> AgentBrain:
    """创建 Agent Brain 实例"""
    return AgentBrain(llm_client=llm_client)
