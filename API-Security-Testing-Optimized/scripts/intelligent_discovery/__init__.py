"""
Intelligent API Discovery Package

真正由 AI 驱动的智能 API 发现系统

核心组件：
- AgentBrain: LLM 决策引擎
- ContextManager: 动态上下文管理
- BrowserCollector: 动态交互引擎
- SourceAnalyzer: 全资源分析
- ResponseAnalyzer: 响应推导
- LearningEngine: 持续学习引擎
- InsightGenerator: 洞察生成器
- StrategyGenerator: 策略生成器
- DiscoveryOrchestrator: 协调器
- EnvironmentChecker: 环境检查器
"""

from .agent_brain import AgentBrain, create_agent_brain
from .context_manager import ContextManager, create_context_manager
from .orchestrator import DiscoveryOrchestrator, run_discovery
from .learning_engine import LearningEngine, create_learning_engine
from .insight_generator import InsightGenerator, create_insight_generator
from .strategy_generator import StrategyGenerator, create_strategy_generator
from .environment import EnvironmentChecker
from .auth_bypass import AuthBypass, create_auth_bypass
from .models import (
    DiscoveryContext, Endpoint, Observation, Insight, Strategy, Action,
    NetworkRequest, Pattern, PageStructure, TechStack, AuthInfo,
    ObservationType, InsightType, ActionType, Finding,
    AnalysisResult, ExecutionResult, Service
)

__version__ = "1.0.0"

__all__ = [
    # Core
    'AgentBrain',
    'create_agent_brain',
    'ContextManager',
    'create_context_manager',
    'DiscoveryOrchestrator',
    'run_discovery',
    
    # Learning
    'LearningEngine',
    'create_learning_engine',
    'InsightGenerator',
    'create_insight_generator',
    'StrategyGenerator',
    'create_strategy_generator',
    
    # Environment
    'EnvironmentChecker',
    'AuthBypass',
    'create_auth_bypass',
    
    # Models
    'DiscoveryContext',
    'Endpoint',
    'Observation',
    'Insight',
    'Strategy',
    'Action',
    'NetworkRequest',
    'Pattern',
    'PageStructure',
    'TechStack',
    'AuthInfo',
    'ObservationType',
    'InsightType',
    'ActionType',
    'Finding',
    'AnalysisResult',
    'ExecutionResult',
    'Service',
]
