#!/usr/bin/env python3
"""
Agentic Orchestrator - 智能编排器
不是简单的 Pipeline 调度，而是有理解能力的流程控制

核心理念：
1. 每个模块输出后，理解其含义
2. 根据当前状态，动态调整策略
3. 不是按顺序执行，而是按需执行
4. 失败时理解原因，而不是简单地继续
"""

import re
import time
from typing import Dict, List, Set, Tuple, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import requests

try:
    from .agentic_analyzer import AgenticAnalyzer, analyze_with_understanding, UnderstandingLevel
    from .response_classifier import ResponseClassifier, ResponseType
    from .smart_analyzer import SmartAPIAnalyzer, smart_analyze
    from .api_fuzzer import APIfuzzer
except ImportError:
    from agentic_analyzer import AgenticAnalyzer, analyze_with_understanding, UnderstandingLevel
    from response_classifier import ResponseClassifier, ResponseType
    from smart_analyzer import SmartAPIAnalyzer, smart_analyze
    from api_fuzzer import APIfuzzer


class StageStatus(Enum):
    """阶段状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ADAPTED = "adapted"  # 调整后完成


class InsightType(Enum):
    """洞察类型"""
    OBSERVATION = "observation"      # 观察到的事实
    PATTERN = "pattern"              # 发现的模式
    INFERENCE = "inference"          # 推断
    BLOCKER = "blocker"              # 阻碍因素
    OPPORTUNITY = "opportunity"      # 机会
    STRATEGY_CHANGE = "strategy"    # 策略调整


@dataclass
class Insight:
    """洞察"""
    type: InsightType
    content: str
    source: str
    confidence: float = 1.0
    action_required: Optional[str] = None


@dataclass
class StageResult:
    """阶段结果"""
    name: str
    status: StageStatus
    duration: float = 0.0
    
    # 输出
    data: Any = None
    
    # 洞察
    insights: List[Insight] = field(default_factory=list)
    
    # 问题
    problems: List[str] = field(default_factory=list)
    
    # 建议
    suggestions: List[str] = field(default_factory=list)
    
    # 下一个阶段
    next_stages: List[str] = field(default_factory=list)
    
    def summary(self) -> str:
        return f"{self.name}: {self.status.value} ({self.duration:.1f}s)"


class AgenticOrchestrator:
    """
    Agentic Orchestrator
    
    不是简单地按顺序执行 Pipeline
    而是：
    1. 执行每个阶段后，理解其输出
    2. 根据洞察动态调整策略
    3. 识别阻碍和机会
    4. 决定下一步
    """
    
    def __init__(self, target: str, session: requests.Session = None):
        self.target = target
        self.session = session or requests.Session()
        
        # 洞察库
        self.insights: List[Insight] = []
        
        # 阶段结果
        self.stage_results: Dict[str, StageResult] = {}
        
        # 当前状态
        self.current_state: Dict[str, Any] = {
            'target': target,
            'tech_stack': {},
            'api_endpoints': [],
            'testable_endpoints': [],
            'unreachable_endpoints': [],
            'high_value_targets': [],
            'vulnerabilities': [],
            'blockers': [],
        }
        
        # 策略
        self.strategy: Dict[str, Any] = {
            'fuzz_enabled': True,
            'browser_enabled': True,
            'auth_test_enabled': True,
            'aggressive': False,
        }
    
    def execute(self) -> Dict:
        """执行编排"""
        print("=" * 70)
        print(" Agentic Security Testing")
        print("=" * 70)
        
        start_time = time.time()
        
        # 阶段 1: 理解目标
        self._stage_understand_target()
        
        # 检查是否有阻碍
        if self._has_blockers():
            self._handle_blockers()
        
        # 阶段 2: 智能侦察
        self._stage_recon()
        
        # 阶段 3: API 发现
        self._stage_discovery()
        
        # 阶段 4: 分类分析
        self._stage_classification()
        
        # 阶段 5: 智能 Fuzzing
        self._stage_fuzzing()
        
        # 阶段 6: 测试
        self._stage_testing()
        
        duration = time.time() - start_time
        
        # 生成报告
        return self._generate_report(duration)
    
    def _add_insight(self, insight: Insight):
        """添加洞察"""
        self.insights.append(insight)
        
        if insight.type == InsightType.BLOCKER:
            self.current_state['blockers'].append(insight.content)
        
        if insight.action_required:
            self._handle_action(insight)
    
    def _has_blockers(self) -> bool:
        """是否有阻碍因素"""
        return len([i for i in self.insights if i.type == InsightType.BLOCKER]) > 0
    
    def _handle_blockers(self):
        """处理阻碍因素"""
        blockers = [i for i in self.insights if i.type == InsightType.BLOCKER]
        
        print(f"\n[!] 发现 {len(blockers)} 个阻碍因素:")
        for b in blockers:
            print(f"    - {b.content}")
            if b.action_required:
                print(f"      行动: {b.action_required}")
    
    def _handle_action(self, insight: Insight):
        """处理洞察要求的行动"""
        if "调整策略" in insight.action_required:
            if "内网" in insight.content:
                self.strategy['fuzz_enabled'] = False
                self.current_state['unreachable_endpoints'].append(insight.content)
                
                self._add_insight(Insight(
                    type=InsightType.STRATEGY_CHANGE,
                    content="调整为代理模式，不再直接 fuzz 后端地址",
                    source="orchestrator",
                    action_required=None
                ))
    
    def _stage_understand_target(self):
        """阶段 1: 理解目标"""
        print("\n[*] Phase 1: 理解目标")
        
        start = time.time()
        
        # 使用 Agentic Analyzer 理解目标
        result = analyze_with_understanding(self.target, self.session)
        
        duration = time.time() - start
        
        # 处理发现
        for finding in result.findings:
            self._add_insight(Insight(
                type=InsightType.INFERENCE,
                content=f"{finding.so_what} | {finding.why}",
                source="understand_target",
                confidence=finding.confidence,
                action_required=finding.strategy if finding.confidence < 0.9 else None
            ))
        
        # 更新状态
        self.current_state['unreachable_endpoints'] = [
            {'url': ep['url'], 'reason': ep.get('reason', '内网地址')}
            for ep in result.unreachable_endpoints
        ]
        
        self.stage_results['understand_target'] = StageResult(
            name="understand_target",
            status=StageStatus.COMPLETED,
            duration=duration,
            data=result.findings,
            insights=[i for i in self.insights if i.source == "understand_target"]
        )
        
        print(f"    完成 ({duration:.1f}s)")
        print(f"    洞察: {len(self.insights)} 个")
    
    def _stage_recon(self):
        """阶段 2: 智能侦察"""
        print("\n[*] Phase 2: 智能侦察")
        
        if not self.strategy.get('recon_enabled', True):
            print("    [跳过] 被策略禁用")
            self.stage_results['recon'] = StageResult(
                name="recon", status=StageStatus.SKIPPED
            )
            return
        
        start = time.time()
        
        # 执行侦察
        from advanced_recon import AdvancedRecon
        recon = AdvancedRecon(self.session)
        result = recon.run(self.target)
        
        duration = time.time() - start
        
        # 分析侦察结果
        if result.tech_stack:
            self.current_state['tech_stack'] = result.tech_stack
            
            self._add_insight(Insight(
                type=InsightType.PATTERN,
                content=f"技术栈: {result.tech_stack}",
                source="recon"
            ))
        
        # Swagger 发现
        if result.swagger_endpoints:
            self._add_insight(Insight(
                type=InsightType.OPPORTUNITY,
                content=f"发现 Swagger 文档: {len(result.swagger_endpoints)} 个",
                source="recon"
            ))
        
        # 检查是否全部是 SPA fallback
        spa_count = 0
        for url in result.swagger_endpoints + result.interesting_urls:
            if url.endswith('/200') or '200' in str(url):
                pass
        
        self.stage_results['recon'] = StageResult(
            name="recon",
            status=StageStatus.COMPLETED,
            duration=duration,
            data=result
        )
        
        print(f"    完成 ({duration:.1f}s)")
        print(f"    技术栈: {result.tech_stack}")
    
    def _stage_discovery(self):
        """阶段 3: API 发现"""
        print("\n[*] Phase 3: API 发现")
        
        start = time.time()
        
        result = smart_analyze(self.target, self.session)
        
        duration = time.time() - start
        
        # 更新状态
        self.current_state['api_endpoints'] = result['high_value']
        self.current_state['testable_endpoints'] = result.get('base_urls', [])
        
        # 分析高价值端点
        if result['high_value']:
            high_value_paths = [ep.path for ep in result['high_value'][:10]]
            self._add_insight(Insight(
                type=InsightType.OPPORTUNITY,
                content=f"发现 {len(result['high_value'])} 个高价值 API 端点",
                source="discovery"
            ))
        
        self.stage_results['discovery'] = StageResult(
            name="discovery",
            status=StageStatus.COMPLETED,
            duration=duration,
            data=result
        )
        
        print(f"    完成 ({duration:.1f}s)")
        print(f"    高价值端点: {len(result['high_value'])}")
    
    def _stage_classification(self):
        """阶段 4: 分类分析"""
        print("\n[*] Phase 4: 分类分析")
        
        start = time.time()
        
        # 使用 ResponseClassifier 分析端点
        classifier = ResponseClassifier(self.session)
        
        test_urls = []
        for ep in self.current_state['api_endpoints'][:20]:
            test_urls.append(self.target + ep.path)
        
        # 添加一些常见端点
        test_urls.extend([
            f"{self.target}/login",
            f"{self.target}/admin",
            f"{self.target}/api",
        ])
        
        results = classifier.classify_batch(test_urls)
        
        # 分析分类结果
        spa_count = 0
        api_count = 0
        
        for r in results:
            if r.response_type == ResponseType.SPA_FALLBACK:
                spa_count += 1
            elif r.response_type == ResponseType.REAL_API_DOC:
                api_count += 1
        
        # 理解分类结果
        if spa_count > 0 and api_count == 0:
            self._add_insight(Insight(
                type=InsightType.BLOCKER,
                content=f"所有 {spa_count} 个测试端点都是 SPA fallback，后端不可达",
                source="classification",
                action_required="需要调整策略，不再直接测试后端"
            ))
        elif api_count > 0:
            self._add_insight(Insight(
                type=InsightType.OPPORTUNITY,
                content=f"发现 {api_count} 个可访问的 API 端点",
                source="classification"
            ))
        
        duration = time.time() - start
        
        self.stage_results['classification'] = StageResult(
            name="classification",
            status=StageStatus.COMPLETED,
            duration=duration,
            data={'results': results, 'spa_count': spa_count, 'api_count': api_count}
        )
        
        print(f"    完成 ({duration:.1f}s)")
        print(f"    SPA Fallback: {spa_count}")
        print(f"    Real API: {api_count}")
    
    def _stage_fuzzing(self):
        """阶段 5: 智能 Fuzzing"""
        print("\n[*] Phase 5: 智能 Fuzzing")
        
        if not self.strategy.get('fuzz_enabled', True):
            print("    [跳过] 被策略禁用 (后端不可达)")
            self.stage_results['fuzzing'] = StageResult(
                name="fuzzing", status=StageStatus.SKIPPED
            )
            return
        
        if self.current_state['blockers']:
            print("    [跳过] 存在阻碍因素")
            self.stage_results['fuzzing'] = StageResult(
                name="fuzzing", status=StageStatus.SKIPPED
            )
            return
        
        start = time.time()
        
        # 使用 APIfuzzer
        fuzzer = APIfuzzer(self.session)
        
        api_paths = [ep.path for ep in self.current_state['api_endpoints']]
        
        targets = fuzzer.generate_parent_fuzz_targets(api_paths)
        results = fuzzer.fuzz_paths(self.target, targets[:100], timeout=2.0)
        
        duration = time.time() - start
        
        # 分析 fuzzing 结果
        alive = fuzzer.get_alive_endpoints()
        high_value = fuzzer.get_high_value_endpoints()
        
        self._add_insight(Insight(
            type=InsightType.PATTERN,
            content=f"Fuzzing: 测试 {len(results)} 个端点，{len(alive)} 个存活，{len(high_value)} 个高价值",
            source="fuzzing"
        ))
        
        self.stage_results['fuzzing'] = StageResult(
            name="fuzzing",
            status=StageStatus.COMPLETED,
            duration=duration,
            data={'results': results, 'alive': len(alive), 'high_value': len(high_value)}
        )
        
        print(f"    完成 ({duration:.1f}s)")
        print(f"    测试: {len(results)}, 存活: {len(alive)}, 高价值: {len(high_value)}")
    
    def _stage_testing(self):
        """阶段 6: 漏洞测试"""
        print("\n[*] Phase 6: 漏洞测试")
        
        if not self.strategy.get('test_enabled', True):
            print("    [跳过]")
            self.stage_results['testing'] = StageResult(
                name="testing", status=StageStatus.SKIPPED
            )
            return
        
        start = time.time()
        
        # 基于洞察决定测试策略
        if self.current_state['blockers']:
            print("    [跳过] 后端不可达，无法进行漏洞测试")
            print("    建议: 通过代理访问内网后进行测试")
            
            self.stage_results['testing'] = StageResult(
                name="testing",
                status=StageStatus.ADAPTED,
                duration=time.time() - start,
                suggestions=["通过代理访问内网", "使用 Burp Suite 监控真实请求"]
            )
            return
        
        # 执行测试...
        # (省略具体实现)
        
        duration = time.time() - start
        
        self.stage_results['testing'] = StageResult(
            name="testing",
            status=StageStatus.COMPLETED,
            duration=duration,
            data={'vulnerabilities': []}
        )
        
        print(f"    完成 ({duration:.1f}s)")
    
    def _generate_report(self, duration: float) -> Dict:
        """生成报告"""
        print("\n" + "=" * 70)
        print(" Agentic Analysis Report")
        print("=" * 70)
        
        print(f"\n执行时间: {duration:.1f}s")
        print(f"目标: {self.target}")
        
        # 洞察总结
        print(f"\n洞察 ({len(self.insights)} 个):")
        for i, insight in enumerate(self.insights, 1):
            icon = {
                InsightType.OBSERVATION: "📌",
                InsightType.PATTERN: "🔍",
                InsightType.INFERENCE: "🤔",
                InsightType.BLOCKER: "🚫",
                InsightType.OPPORTUNITY: "✨",
                InsightType.STRATEGY_CHANGE: "🔄",
            }.get(insight.type, "•")
            
            print(f"  {icon} [{insight.type.value}] {insight.content}")
        
        # 阻碍因素
        blockers = [i for i in self.insights if i.type == InsightType.BLOCKER]
        if blockers:
            print(f"\n阻碍因素 ({len(blockers)}):")
            for b in blockers:
                print(f"  🚫 {b.content}")
        
        # 机会
        opportunities = [i for i in self.insights if i.type == InsightType.OPPORTUNITY]
        if opportunities:
            print(f"\n机会 ({len(opportunities)}):")
            for o in opportunities:
                print(f"  ✨ {o.content}")
        
        # 策略调整
        strategy_changes = [i for i in self.insights if i.type == InsightType.STRATEGY_CHANGE]
        if strategy_changes:
            print(f"\n策略调整 ({len(strategy_changes)}):")
            for s in strategy_changes:
                print(f"  🔄 {s.content}")
        
        # 状态摘要
        print(f"\n状态摘要:")
        print(f"  技术栈: {self.current_state['tech_stack']}")
        print(f"  API 端点: {len(self.current_state['api_endpoints'])}")
        print(f"  高价值: {len(self.current_state['high_value_targets'])}")
        print(f"  不可达: {len(self.current_state['unreachable_endpoints'])}")
        
        # 建议
        if blockers:
            print(f"\n建议:")
            print(f"  1. 后端 API 在内网 ({self.current_state['unreachable_endpoints'][0] if self.current_state['unreachable_endpoints'] else ''})")
            print(f"  2. 使用代理工具 (如 Burp Suite) 访问内网")
            print(f"  3. 寻找外网暴露的测试环境")
        
        print("\n" + "=" * 70)
        
        return {
            'target': self.target,
            'duration': duration,
            'insights': self.insights,
            'state': self.current_state,
            'stage_results': self.stage_results,
            'strategy': self.strategy,
        }


def run_agentic_test(target: str) -> Dict:
    """运行 Agentic 测试"""
    orchestrator = AgenticOrchestrator(target)
    return orchestrator.execute()


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://49.65.100.160:6004"
    run_agentic_test(target)
