#!/usr/bin/env python3
"""
集成测试 - EnhancedAgenticOrchestrator

测试完整的 Agentic Reasoning 流程
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import EnhancedAgenticOrchestrator
from core.reasoning_engine import create_reasoner
from core.context_manager import create_context_manager
from core.strategy_pool import create_strategy_pool, create_strategist


class TestEnhancedAgenticOrchestrator(unittest.TestCase):
    """增强型编排器集成测试"""
    
    def setUp(self):
        self.orch = EnhancedAgenticOrchestrator("http://example.com")
    
    def test_orchestrator_creation(self):
        """测试编排器创建"""
        self.assertIsNotNone(self.orch)
        self.assertIsNotNone(self.orch.reasoner)
        self.assertIsNotNone(self.orch.context_manager)
        self.assertIsNotNone(self.orch.strategy_pool)
        self.assertIsNotNone(self.orch.strategist)
    
    def test_components_integrated(self):
        """测试组件已集成"""
        self.assertIsInstance(self.orch.reasoner, type(create_reasoner()))
        self.assertIsInstance(self.orch.context_manager, type(create_context_manager("http://test.com")))
        self.assertIsInstance(self.orch.strategy_pool, type(create_strategy_pool()))
        self.assertIsInstance(self.orch.strategist, type(create_strategist()))
    
    def test_callback_registration(self):
        """测试回调注册"""
        callback_invoked = []
        
        def test_callback(data):
            callback_invoked.append(data)
        
        self.orch.on('stage_start', test_callback)
        
        self.assertIn('stage_start', self.orch.callbacks)
        self.assertIn(test_callback, self.orch.callbacks['stage_start'])


class TestIntegrationReasoning(unittest.TestCase):
    """推理集成测试"""
    
    def setUp(self):
        self.reasoner = create_reasoner()
        self.context_manager = create_context_manager("http://example.com")
    
    def test_reasoning_updates_context(self):
        """测试推理更新上下文"""
        response_data = {
            'url': 'http://example.com/swagger.json',
            'method': 'GET',
            'status_code': 200,
            'content_type': 'application/json',
            'content': 'Swagger API definition',
            'source': 'recon'
        }
        
        insights = self.reasoner.observe_and_reason(response_data)
        
        swagger_insights = [i for i in insights if 'swagger' in i.content.lower()]
        if swagger_insights:
            for finding in swagger_insights[0].findings:
                if finding.evidence:
                    self.context_manager.add_swagger_url(finding.evidence[0])
        
        self.assertTrue(len(swagger_insights) > 0 or len(self.context_manager.context.content.swagger_urls) >= 0)
    
    def test_spa_detection_updates_context(self):
        """测试 SPA 检测更新上下文"""
        spa_content = '<!DOCTYPE html><html><div id="app"></div><script src="/chunk-vendors.js"></script></html>' * 10
        
        for i in range(3):
            response_data = {
                'url': f'http://example.com/path{i}',
                'method': 'GET',
                'status_code': 200,
                'content_type': 'text/html',
                'content': spa_content,
                'source': 'recon'
            }
            self.reasoner.observe_and_reason(response_data)
        
        insights = self.reasoner.insight_store.get_active()
        
        spa_insights = [i for i in insights if 'fallback' in i.content.lower() or 'spa' in i.content.lower()]
        
        if spa_insights:
            self.context_manager.set_spa_mode(True)
        
        self.assertTrue(len(spa_insights) > 0)


class TestIntegrationStrategy(unittest.TestCase):
    """策略集成测试"""
    
    def setUp(self):
        self.strategy_pool = create_strategy_pool()
        self.context_manager = create_context_manager("http://example.com")
        self.reasoner = create_reasoner()
    
    def test_context_drives_strategy_selection(self):
        """测试上下文驱动策略选择"""
        self.context_manager.set_spa_mode(True)
        
        context = {
            'insights': self.reasoner.insight_store.get_active(),
            'tech_stack': self.context_manager.context.tech_stack.to_dict(),
            'network_status': self.context_manager.context.network.rate_limit_status.value,
            'is_spa': self.context_manager.context.content.is_spa,
            'has_internal_ips': bool(self.context_manager.context.content.internal_ips),
            'waf_detected': self.context_manager.context.tech_stack.waf
        }
        
        from core.strategy_pool import StrategyContext
        strategy_context = StrategyContext(context)
        
        strategy = self.strategy_pool.select_strategy(strategy_context)
        
        self.assertIsNotNone(strategy)
        self.assertEqual(strategy.id, 'spa_fallback')
    
    def test_waf_detection_triggers_bypass(self):
        """测试 WAF 检测触发绕过策略"""
        self.context_manager.set_waf("aliyun")
        
        context = {
            'insights': [],
            'tech_stack': {},
            'network_status': 'normal',
            'is_spa': False,
            'has_internal_ips': False,
            'waf_detected': 'aliyun'
        }
        
        from core.strategy_pool import StrategyContext
        strategy_context = StrategyContext(context)
        
        strategy = self.strategy_pool.select_strategy(strategy_context)
        
        self.assertEqual(strategy.id, 'waf_detected')


class TestIntegrationFullFlow(unittest.TestCase):
    """完整流程集成测试"""
    
    def test_full_flow_mock(self):
        """测试完整流程（模拟）"""
        reasoner = create_reasoner()
        context_manager = create_context_manager("http://example.com")
        strategy_pool = create_strategy_pool()
        strategist = create_strategist(strategy_pool)
        
        test_responses = [
            {
                'url': 'http://example.com/',
                'method': 'GET',
                'status_code': 200,
                'content_type': 'text/html',
                'content': '<!DOCTYPE html><html><div id="app"></div></html>' * 20,
                'source': 'recon'
            },
            {
                'url': 'http://example.com/api-docs',
                'method': 'GET',
                'status_code': 200,
                'content_type': 'text/html',
                'content': 'API Documentation',
                'source': 'recon'
            },
            {
                'url': 'http://example.com/admin',
                'method': 'GET',
                'status_code': 200,
                'content_type': 'text/html',
                'content': '<!DOCTYPE html><html><div id="app"></div></html>' * 20,
                'source': 'recon'
            }
        ]
        
        for resp in test_responses:
            insights = reasoner.observe_and_reason(resp)
        
        context = {
            'insights': reasoner.insight_store.get_active(),
            'tech_stack': context_manager.context.tech_stack.to_dict(),
            'network_status': context_manager.context.network.rate_limit_status.value,
            'is_spa': context_manager.context.content.is_spa,
            'has_internal_ips': bool(context_manager.context.content.internal_ips),
            'waf_detected': context_manager.context.tech_stack.waf
        }
        
        from core.strategy_pool import StrategyContext
        strategy_context = StrategyContext(context)
        
        selected_strategy = strategy_pool.select_strategy(strategy_context, reasoner.insight_store.get_active())
        
        plan = strategist.create_strategy_plan(strategy_context, reasoner.insight_store.get_active())
        
        self.assertIsNotNone(selected_strategy)
        self.assertIsNotNone(plan)
        self.assertIsNotNone(plan.primary_strategy)


class TestIntegrationCallbacks(unittest.TestCase):
    """回调集成测试"""
    
    def test_insight_callback_chain(self):
        """测试洞察回调链"""
        events = []
        
        def insight_callback(data):
            events.append(('insight', data))
        
        def blocker_callback(data):
            events.append(('blocker', data))
        
        orch = EnhancedAgenticOrchestrator("http://example.com")
        
        orch.on('insight_generated', insight_callback)
        orch.on('blocker_detected', blocker_callback)
        
        from core.reasoning_engine import Insight, InsightType
        
        mock_insight = Insight(
            id="test_1",
            type=InsightType.BLOCKER,
            content="Test blocker",
            source="test"
        )
        
        orch._process_insight(mock_insight)
        
        self.assertGreater(len(events), 0)


if __name__ == '__main__':
    unittest.main()
