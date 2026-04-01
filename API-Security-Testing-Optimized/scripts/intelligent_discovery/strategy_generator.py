"""
Intelligent API Discovery - Strategy Generator

策略生成器，负责：
1. 基于洞察和上下文生成发现策略
2. 决定下一步动作
3. 为 Agent Brain 提供决策支持
"""

import json
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass

from .models import (
    DiscoveryContext, Insight, Strategy, Action, ActionType,
    Observation, InsightType, PageStructure, Endpoint
)


LLM_STRATEGY_PROMPT = """基于以下信息，生成发现策略。

目标：{target}
已发现端点：{endpoints}
技术栈：{tech_stack}
API Base：{api_base}
探索历史：{history}

当前洞察：
{insights}

学习反馈：
{learning_feedback}

请生成发现策略，选择最有可能发现新端点的动作序列。

输出 JSON 格式：
{{
  "reasoning": "策略推理过程",
  "expected_outcome": "期望结果",
  "confidence": 0.0-1.0,
  "actions": [
    {{
      "type": "NAVIGATE|CLICK|TYPE|SCROLL|WAIT|FETCH_API|ANALYZE_SOURCE",
      "target": "目标 URL 或选择器",
      "params": {{}},
      "reasoning": "为什么执行这个动作"
    }}
  ]
}}"""


class StrategyGenerator:
    """
    策略生成器
    
    基于上下文和洞察生成发现策略
    """
    
    def __init__(self, llm_client=None, learning_engine=None):
        self.llm_client = llm_client
        self.learning_engine = learning_engine
    
    def generate(
        self,
        context: DiscoveryContext,
        insights: List[Insight]
    ) -> Strategy:
        """
        生成发现策略
        
        Args:
            context: 发现上下文
            insights: 当前洞察列表
            
        Returns:
            Strategy: 生成的策略
        """
        if self.llm_client:
            return self._generate_with_llm(context, insights)
        else:
            return self._generate_fallback(context, insights)
    
    def _generate_with_llm(
        self,
        context: DiscoveryContext,
        insights: List[Insight]
    ) -> Strategy:
        """使用 LLM 生成策略"""
        learning_summary = ""
        if self.learning_engine:
            summary = self.learning_engine.get_learning_summary()
            learning_summary = json.dumps(summary, indent=2)
        
        prompt = LLM_STRATEGY_PROMPT.format(
            target=context.target,
            endpoints=self._summarize_endpoints(context.discovered_endpoints),
            tech_stack=context.tech_stack.to_dict(),
            api_base=context.api_base or "unknown",
            history=self._summarize_history(context.exploration_history),
            insights=self._summarize_insights(insights),
            learning_feedback=learning_summary or "无"
        )
        
        try:
            response = self.llm_client.generate(prompt)
            data = json.loads(response)
            
            actions = []
            for a in data.get("actions", []):
                action_type = a.get("type", "WAIT")
                if hasattr(ActionType, action_type):
                    action_type = ActionType[action_type]
                else:
                    action_type = ActionType.WAIT
                
                actions.append(Action(
                    type=action_type,
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
        
        except (json.JSONDecodeError, KeyError, Exception):
            return self._generate_fallback(context, insights)
    
    def _generate_fallback(
        self,
        context: DiscoveryContext,
        insights: List[Insight]
    ) -> Strategy:
        """
        回退策略生成（启发式）
        
        这不是硬编码规则，而是 LLM 不可用时的默认行为
        """
        actions = []
        reasoning_parts = []
        
        # 1. 如果没有页面结构，先导航获取
        if not context.page_structures:
            actions.append(Action(
                type=ActionType.NAVIGATE,
                target=context.target,
                reasoning="初始探索：获取页面结构"
            ))
            reasoning_parts.append("从初始导航开始")
            return Strategy(
                actions=actions,
                reasoning="; ".join(reasoning_parts),
                expected_outcome="获取页面结构",
                confidence=0.5
            )
        
        # 2. 基于上下文生成多样化的动作
        last_page = context.page_structures[-1]
        exploration_count = len(context.exploration_history)
        
        # 根据探索次数选择不同策略
        if exploration_count < 3:
            # 早期阶段：收集页面信息
            if last_page.forms:
                actions.append(Action(
                    type=ActionType.TYPE,
                    target="input[type='text']",
                    params={"text": "admin"},
                    reasoning="输入测试数据"
                ))
                reasoning_parts.append("输入测试数据")
                
                actions.append(Action(
                    type=ActionType.TYPE,
                    target="input[type='password']",
                    params={"text": "admin"},
                    reasoning="输入密码"
                ))
                reasoning_parts.append("输入密码")
            
            actions.append(Action(
                type=ActionType.SCROLL,
                target="current_page",
                params={"direction": "down", "amount": 500},
                reasoning="向下滚动"
            ))
            reasoning_parts.append("向下滚动探索")
        
        elif exploration_count < 10:
            # 中期阶段：尝试交互
            if last_page.interactive_elements:
                for elem in last_page.interactive_elements[:3]:
                    if elem.get("type") in ["button", "link"]:
                        actions.append(Action(
                            type=ActionType.CLICK,
                            target=elem.get("selector"),
                            reasoning=f"点击 {elem.get('description', elem.get('type'))}"
                        ))
                        reasoning_parts.append(f"点击 {elem.get('type')}")
                        if len(actions) >= 3:
                            break
            
            if len(actions) < 2:
                actions.append(Action(
                    type=ActionType.SCROLL,
                    target="current_page",
                    params={"direction": "down", "amount": 1000},
                    reasoning="滚动页面"
                ))
                reasoning_parts.append("滚动探索")
        
        else:
            # 后期阶段：深度探索和尝试其他方法
            directions = ["down", "up", "left", "right"]
            for i in range(2):
                actions.append(Action(
                    type=ActionType.SCROLL,
                    target="current_page",
                    params={"direction": directions[i % 4], "amount": 500},
                    reasoning=f"滚动探索 {directions[i % 4]}"
                ))
                reasoning_parts.append(f"滚动{directions[i % 4]}")
        
        # 始终添加等待动作
        actions.append(Action(
            type=ActionType.WAIT,
            target=None,
            params={"seconds": 2},
            reasoning="等待网络请求完成"
        ))
        
        # 添加滚动后再次滚动（触发懒加载）
        if exploration_count > 0:
            actions.append(Action(
                type=ActionType.SCROLL,
                target="current_page",
                params={"direction": "down", "amount": 2000},
                reasoning="快速滚动触发懒加载"
            ))
        
        return Strategy(
            actions=actions,
            reasoning="; ".join(reasoning_parts) if reasoning_parts else "多样化探索策略",
            expected_outcome="发现更多 API 端点",
            confidence=0.5
        )
    
    def decide_next_action(
        self,
        context: DiscoveryContext
    ) -> Tuple[Action, str]:
        """
        决定下一步动作
        
        Args:
            context: 发现上下文
            
        Returns:
            Tuple[Action, priority]: 动作和优先级
        """
        if self.learning_engine:
            best_action_type = self.learning_engine.get_best_action_for_context(context)
            confidence = self.learning_engine.get_action_confidence(best_action_type)
        else:
            best_action_type = ActionType.NAVIGATE
            confidence = 0.5
        
        action = self._create_action_for_type(best_action_type, context)
        
        priority = "high" if confidence > 0.7 else "medium" if confidence > 0.4 else "low"
        
        return action, priority
    
    def _create_action_for_type(
        self,
        action_type: ActionType,
        context: DiscoveryContext
    ) -> Action:
        """为指定动作类型创建动作"""
        if action_type == ActionType.NAVIGATE:
            return Action(
                type=ActionType.NAVIGATE,
                target=context.target,
                reasoning="导航到目标"
            )
        
        elif action_type == ActionType.ANALYZE_SOURCE:
            return Action(
                type=ActionType.ANALYZE_SOURCE,
                target="current_page",
                reasoning="分析当前页面资源"
            )
        
        elif action_type == ActionType.CLICK:
            if context.page_structures:
                for page in reversed(context.page_structures):
                    for element in page.interactive_elements:
                        if element.get("type") == "button":
                            return Action(
                                type=ActionType.CLICK,
                                target=element.get("selector"),
                                reasoning=f"点击按钮: {element.get('description', '')}"
                            )
            return Action(
                type=ActionType.CLICK,
                target="button:first-of-type",
                reasoning="点击第一个按钮"
            )
        
        elif action_type == ActionType.TYPE:
            if context.page_structures:
                for page in reversed(context.page_structures):
                    if page.forms:
                        form = page.forms[0]
                        fields = form.get("fields", [])
                        if fields:
                            return Action(
                                type=ActionType.TYPE,
                                target=f"input[name='{fields[0]}']",
                                params={"text": "test"},
                                reasoning=f"输入到字段: {fields[0]}"
                            )
            return Action(
                type=ActionType.TYPE,
                target="input[type='text']",
                params={"text": "admin"},
                reasoning="输入测试数据"
            )
        
        elif action_type == ActionType.SCROLL:
            return Action(
                type=ActionType.SCROLL,
                target="current_page",
                params={"direction": "down"},
                reasoning="向下滚动"
            )
        
        elif action_type == ActionType.WAIT:
            return Action(
                type=ActionType.WAIT,
                target=None,
                params={"seconds": 2},
                reasoning="等待"
            )
        
        else:
            return Action(
                type=ActionType.WAIT,
                target=None,
                reasoning="默认等待"
            )
    
    def _summarize_endpoints(self, endpoints: List[Endpoint]) -> str:
        """总结端点"""
        if not endpoints:
            return "暂无"
        
        lines = []
        for ep in endpoints[:10]:
            lines.append(f"  {ep.method} {ep.path} (置信度: {ep.confidence:.2f})")
        
        if len(endpoints) > 10:
            lines.append(f"  ... 还有 {len(endpoints) - 10} 个")
        
        return "\n".join(lines)
    
    def _summarize_history(self, actions: List[Action]) -> str:
        """总结历史"""
        if not actions:
            return "暂无"
        
        lines = []
        for a in actions[-5:]:
            lines.append(f"  {a.type.value}: {a.target}")
        
        return "\n".join(lines)
    
    def _summarize_insights(self, insights: List[Insight]) -> str:
        """总结洞察"""
        if not insights:
            return "暂无"
        
        lines = []
        for i in insights[:5]:
            lines.append(f"  [{i.type.value}] {i.content[:50]}...")
        
        return "\n".join(lines)


def create_strategy_generator(llm_client=None, learning_engine=None) -> StrategyGenerator:
    """创建策略生成器"""
    return StrategyGenerator(llm_client=llm_client, learning_engine=learning_engine)
