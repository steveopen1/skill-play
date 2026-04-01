"""
Intelligent API Discovery Package

真正由 AI 驱动的智能 API 发现系统

核心组件：
- AgentBrain: LLM 决策引擎
- BrowserCollector: 动态交互引擎
- SourceAnalyzer: 全资源分析
- ResponseAnalyzer: 响应推导
- DiscoveryOrchestrator: 协调器
"""

from .agent_brain import AgentBrain, create_agent_brain
from .context_manager import ContextManager, create_context_manager
from .orchestrator import DiscoveryOrchestrator, run_discovery
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
