"""
API Security Testing Skill
Agent驱动的自动化API渗透测试

模块结构:
- orchestrator: 智能编排器，整合所有组件
- collectors_coordinator: 采集器联动管理器
- collectors: 采集器模块包
│   ├── js_collector: JS文件分析采集器
│   ├── api_path_finder: API路径发现采集器
│   ├── url_collector: URL采集器
│   └── browser_collector: 无头浏览器采集器
- api_fuzzer: API路径模糊测试器
- scan_engine: 统一扫描引擎
- reasoning_engine: 多层级推理引擎
- context_manager: 上下文管理器
- strategy_pool: 策略池系统
- testing_loop: 洞察驱动测试循环
- api_tester: API测试执行器
- report_generator: 报告生成器
- models: 数据模型
"""

from .orchestrator import EnhancedAgenticOrchestrator, run_enhanced_agentic_test
from .reasoning_engine import Reasoner, Insight, InsightType, create_reasoner
from .context_manager import ContextManager, create_context_manager
from .strategy_pool import StrategyPool, Strategist, create_strategy_pool, create_strategist
from .testing_loop import InsightDrivenLoop, create_test_loop
from .api_tester import APITester
from .report_generator import ReportGenerator
from .collectors_coordinator import CollectorsCoordinator, create_coordinator
from .models import APIEndpoint, Vulnerability, ScanResult

__version__ = "3.0"
__all__ = [
    "EnhancedAgenticOrchestrator",
    "run_enhanced_agentic_test",
    "Reasoner",
    "Insight",
    "InsightType", 
    "create_reasoner",
    "ContextManager",
    "create_context_manager",
    "StrategyPool",
    "Strategist",
    "create_strategy_pool",
    "create_strategist",
    "InsightDrivenLoop",
    "create_test_loop",
    "APITester",
    "ReportGenerator",
    "CollectorsCoordinator",
    "create_coordinator",
    "APIEndpoint",
    "Vulnerability",
    "ScanResult",
]
