"""
Intelligent API Discovery - Learning Engine

持续学习引擎，负责：
1. 从发现过程中学习模式
2. 更新置信度
3. 优化后续决策
"""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from .models import (
    DiscoveryContext, Endpoint, Action, ActionType, Insight,
    NetworkRequest, Pattern, Observation, ObservationType
)


@dataclass
class LearningRecord:
    """学习记录"""
    action: Action
    result: bool
    new_endpoints_found: int
    timestamp: datetime
    context_snapshot: Dict


@dataclass
class PatternLearned:
    """学习到的模式"""
    pattern_type: str  # url, parameter, tech_stack
    pattern_value: str
    success_rate: float
    total_attempts: int
    successful_attempts: int
    last_success: datetime
    examples: List[str] = field(default_factory=list)


class LearningEngine:
    """
    持续学习引擎
    
    从发现过程中学习，优化后续决策
    """
    
    def __init__(self):
        self._records: List[LearningRecord] = []
        self._patterns: Dict[str, PatternLearned] = {}
        self._action_success_rates: Dict[str, float] = defaultdict(float)
        self._endpoint_source_weights: Dict[str, float] = {}
        self._explorationStrategies: List[str] = []
    
    def record_decision(
        self,
        action: Action,
        result: bool,
        context: DiscoveryContext,
        new_endpoints: int = 0
    ):
        """
        记录决策结果
        
        Args:
            action: 执行的动作
            result: 是否成功
            context: 执行时的上下文
            new_endpoints: 新发现的端点数量
        """
        record = LearningRecord(
            action=action,
            result=result,
            new_endpoints_found=new_endpoints,
            timestamp=datetime.now(),
            context_snapshot=self._snapshot_context(context)
        )
        
        self._records.append(record)
        
        self._update_action_success_rate(action, result, new_endpoints)
        
        if result and new_endpoints > 0:
            self._learn_from_success(action, context)
    
    def _update_action_success_rate(
        self,
        action: Action,
        result: bool,
        new_endpoints: int
    ):
        """更新动作成功率"""
        key = action.type.value
        
        current = self._action_success_rates[key]
        weight = 0.3
        
        if new_endpoints > 0:
            success_score = 1.0 + min(new_endpoints * 0.1, 0.5)
        elif result:
            success_score = 0.8
        else:
            success_score = 0.2
        
        self._action_success_rates[key] = current * (1 - weight) + success_score * weight
    
    def _learn_from_success(
        self,
        action: Action,
        context: DiscoveryContext
    ):
        """从成功的动作中学习"""
        if action.type == ActionType.ANALYZE_SOURCE:
            for endpoint in context.discovered_endpoints[-5:]:
                if endpoint.source == "llm_analysis" or endpoint.source == "js_regex":
                    self._update_pattern(
                        "endpoint_source",
                        endpoint.source,
                        success=True,
                        example=endpoint.path
                    )
        
        if action.type == ActionType.CLICK or action.type == ActionType.TYPE:
            if context.page_structures:
                last_page = context.page_structures[-1]
                self._update_pattern(
                    "interaction_strategy",
                    f"{action.type.value}_on_page",
                    success=True,
                    example=f"Page: {last_page.url}"
                )
    
    def _update_pattern(
        self,
        pattern_type: str,
        pattern_value: str,
        success: bool,
        example: str = ""
    ):
        """更新模式的学习状态"""
        key = f"{pattern_type}:{pattern_value}"
        
        if key not in self._patterns:
            self._patterns[key] = PatternLearned(
                pattern_type=pattern_type,
                pattern_value=pattern_value,
                success_rate=0.5,
                total_attempts=0,
                successful_attempts=0,
                last_success=datetime.now()
            )
        
        p = self._patterns[key]
        p.total_attempts += 1
        
        if success:
            p.successful_attempts += 1
            p.last_success = datetime.now()
            if example and example not in p.examples:
                p.examples.append(example)
        
        p.success_rate = p.successful_attempts / p.total_attempts
    
    def extract_patterns(self) -> List[Pattern]:
        """
        从历史中提取发现的模式
        
        Returns:
            List[Pattern]: 发现的模式列表
        """
        patterns = []
        
        url_parts = defaultdict(list)
        for record in self._records[-50:]:
            action = record.action
            if action.type == ActionType.NAVIGATE and action.target:
                parts = action.target.strip('/').split('/')
                for i, part in enumerate(parts):
                    if '{' not in part and not part.isdigit():
                        url_parts[i].append(part)
        
        for position, parts in url_parts.items():
            if len(parts) > 2:
                most_common = max(set(parts), key=parts.count)
                pattern = "/".join(["{" + f"seg{i}" + "}" if i <= position else "?" 
                                   for i in range(position + 2)])
                patterns.append(Pattern(
                    template=f"/{most_common}/{pattern}",
                    example=most_common,
                    confidence=0.7
                ))
        
        return patterns[:10]
    
    def get_best_action_for_context(self, context: DiscoveryContext) -> ActionType:
        """
        根据当前上下文获取最佳动作类型
        
        Args:
            context: 当前上下文
            
        Returns:
            ActionType: 推荐的动作类型
        """
        context_factors = {
            'has_page': len(context.page_structures) > 0,
            'has_js': any(s.scripts for s in context.page_structures[-1:]),
            'has_forms': any(s.forms for s in context.page_structures[-1:]),
            'low_discovery_rate': self._calculate_discovery_rate() < 0.3,
            'many_endpoints': len(context.discovered_endpoints) > 10
        }
        
        if context_factors['many_endpoints'] and context_factors['low_discovery_rate']:
            return ActionType.ANALYZE_SOURCE
        
        if context_factors['has_forms']:
            return ActionType.TYPE
        
        if context_factors['has_page']:
            return ActionType.CLICK
        
        return ActionType.NAVIGATE
    
    def _calculate_discovery_rate(self) -> float:
        """计算发现率（每步发现的新端点数量）"""
        if len(self._records) < 2:
            return 0.5
        
        recent = self._records[-10:]
        if not recent:
            return 0.0
        
        total_new = sum(r.new_endpoints_found for r in recent)
        return total_new / len(recent)
    
    def get_action_confidence(self, action_type: ActionType) -> float:
        """
        获取动作的置信度
        
        Args:
            action_type: 动作类型
            
        Returns:
            float: 置信度 (0.0-1.0)
        """
        return self._action_success_rates.get(action_type.value, 0.5)
    
    def get_recommended_strategies(self) -> List[str]:
        """
        获取推荐的策略列表
        
        Returns:
            List[str]: 策略描述列表
        """
        strategies = []
        
        high_performers = [
            (at, rate) 
            for at, rate in self._action_success_rates.items()
            if rate > 0.7
        ]
        
        for action_type, rate in sorted(high_performers, key=lambda x: -x[1])[:3]:
            strategies.append(f"Use {action_type} (confidence: {rate:.2f})")
        
        low_performers = [
            (at, rate)
            for at, rate in self._action_success_rates.items()
            if rate < 0.3
        ]
        
        for action_type, rate in low_performers:
            strategies.append(f"Avoid {action_type} (confidence: {rate:.2f})")
        
        return strategies
    
    def learn_from_response(
        self,
        response: NetworkRequest,
        context: DiscoveryContext
    ):
        """
        从 API 响应中学习
        
        Args:
            response: API 响应
            context: 当前上下文
        """
        if not response.response_body:
            return
        
        try:
            import json
            data = json.loads(response.response_body)
            
            if isinstance(data, dict):
                if 'page' in data or 'pagination' in data:
                    self._update_pattern(
                        "response_pattern",
                        "pagination",
                        success=True,
                        example=f"Page {data.get('page', '?')}"
                    )
                
                if 'data' in data and isinstance(data['data'], list):
                    self._update_pattern(
                        "response_pattern",
                        "list_response",
                        success=True,
                        example=f"Items: {len(data['data'])}"
                    )
                
                if '_links' in data or 'links' in data:
                    self._update_pattern(
                        "response_pattern",
                        "hateoas",
                        success=True,
                        example="Found HATEOAS links"
                    )
        
        except (json.JSONDecodeError, TypeError):
            pass
    
    def get_learning_summary(self) -> Dict:
        """
        获取学习摘要
        
        Returns:
            Dict: 学习摘要
        """
        return {
            "total_records": len(self._records),
            "patterns_learned": len(self._patterns),
            "action_success_rates": dict(self._action_success_rates),
            "discovery_rate": self._calculate_discovery_rate(),
            "recommended_strategies": self.get_recommended_strategies(),
            "top_patterns": [
                {
                    "type": p.pattern_type,
                    "value": p.pattern_value,
                    "success_rate": p.success_rate,
                    "examples": p.examples[:3]
                }
                for p in sorted(
                    self._patterns.values(),
                    key=lambda x: -x.success_rate
                )[:5]
            ]
        }
    
    def _snapshot_context(self, context: DiscoveryContext) -> Dict:
        """创建上下文快照"""
        return {
            "endpoint_count": len(context.discovered_endpoints),
            "page_count": len(context.page_structures),
            "exploration_count": len(context.exploration_history),
            "tech_stack": context.tech_stack.to_dict()
        }
    
    def export_learning_data(self) -> Dict:
        """导出学习数据"""
        return {
            "records": [
                {
                    "action": r.action.to_dict(),
                    "result": r.result,
                    "new_endpoints": r.new_endpoints_found,
                    "timestamp": r.timestamp.isoformat()
                }
                for r in self._records[-100:]
            ],
            "patterns": {
                key: {
                    "type": p.pattern_type,
                    "value": p.pattern_value,
                    "success_rate": p.success_rate,
                    "total_attempts": p.total_attempts,
                    "examples": p.examples
                }
                for key, p in self._patterns.items()
            },
            "action_rates": dict(self._action_success_rates)
        }


def create_learning_engine() -> LearningEngine:
    """创建学习引擎"""
    return LearningEngine()
