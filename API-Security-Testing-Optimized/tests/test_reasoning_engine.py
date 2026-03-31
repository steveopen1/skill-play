#!/usr/bin/env python3
"""
单元测试 - ReasoningEngine
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.reasoning_engine import (
    Reasoner, Insight, InsightType, UnderstandingLevel,
    Observation, Finding, InsightStore, ReasoningRule,
    create_reasoner
)


class TestReasoningEngine(unittest.TestCase):
    """推理引擎测试"""
    
    def setUp(self):
        self.reasoner = Reasoner()
    
    def test_reasoner_creation(self):
        """测试推理引擎创建"""
        self.assertIsNotNone(self.reasoner)
        self.assertIsInstance(self.reasoner.rules, list)
        self.assertGreater(len(self.reasoner.rules), 0)
    
    def test_default_rules_registered(self):
        """测试默认规则已注册"""
        rule_names = [r.name for r in self.reasoner.rules]
        
        expected_rules = [
            'internal_ip_discovery',
            'waf_detection',
            'spa_fallback_detection',
            'json_request_html_response',
            'swagger_discovery',
            'error_leak_detection',
            'auth_detection',
            'tech_fingerprint'
        ]
        
        for rule_name in expected_rules:
            self.assertIn(rule_name, rule_names)
    
    def test_rule_priorities(self):
        """测试规则优先级排序"""
        priorities = [r.priority for r in self.reasoner.rules]
        self.assertEqual(priorities, sorted(priorities, reverse=True))
    
    def test_observe_and_reason_spa(self):
        """测试 SPA Fallback 检测"""
        response_data = {
            'url': 'http://example.com/login',
            'method': 'GET',
            'status_code': 200,
            'content_type': 'text/html',
            'content': '<!DOCTYPE html><html><div id="app"></div><script src="/chunk-vendors.js"></script></html>' * 10,
            'source': 'html',
            'response_time': 0.5
        }
        
        # 先发送多个相同响应以触发 SPA 模式
        for i in range(3):
            self.reasoner.observe_and_reason(response_data)
        
        insights = self.reasoner.insight_store.get_active()
        
        spa_insights = [i for i in insights if 'spa' in i.content.lower() or 'fallback' in i.content.lower()]
        self.assertGreater(len(spa_insights), 0)
    
    def test_observe_and_reason_waf(self):
        """测试 WAF 检测"""
        response_data = {
            'url': 'http://example.com/api/test',
            'method': 'GET',
            'status_code': 403,
            'content_type': 'text/html',
            'content': '<html><body>403 Forbidden - 360waf protection</body></html>',
            'source': 'api',
            'response_time': 0.1
        }
        
        insights = self.reasoner.observe_and_reason(response_data)
        
        waf_insights = [i for i in insights if 'waf' in i.content.lower()]
        self.assertGreater(len(waf_insights), 0)
    
    def test_observe_and_reason_swagger(self):
        """测试 Swagger 发现"""
        response_data = {
            'url': 'http://example.com/swagger-ui.html',
            'method': 'GET',
            'status_code': 200,
            'content_type': 'text/html',
            'content': '<html><body>Swagger UI</body></html>',
            'source': 'api',
            'response_time': 0.3
        }
        
        insights = self.reasoner.observe_and_reason(response_data)
        
        swagger_insights = [i for i in insights if 'swagger' in i.content.lower() or 'api' in i.content.lower()]
        self.assertGreater(len(swagger_insights), 0)
    
    def test_insight_store(self):
        """测试洞察存储"""
        response_data = {
            'url': 'http://example.com/test',
            'method': 'GET',
            'status_code': 200,
            'content_type': 'text/html',
            'content': 'test content',
            'source': 'test'
        }
        
        self.reasoner.observe_and_reason(response_data)
        
        store = self.reasoner.insight_store
        self.assertIsInstance(store.insights, list)
        
        summary = store.get_summary()
        self.assertIn('total_insights', summary)
        self.assertIn('active_insights', summary)
    
    def test_insight_to_dict(self):
        """测试洞察序列化"""
        insight = Insight(
            id="test_1",
            type=InsightType.OBSERVATION,
            content="Test insight",
            source="test",
            confidence=0.9
        )
        
        d = insight.to_dict()
        
        self.assertEqual(d['id'], 'test_1')
        self.assertEqual(d['type'], 'observation')
        self.assertEqual(d['content'], 'Test insight')
        self.assertEqual(d['confidence'], 0.9)
    
    def test_custom_rule_registration(self):
        """测试自定义规则注册"""
        def custom_condition(obs, history):
            return 'custom' in obs.url.lower()
        
        def custom_finding(obs, history):
            return Finding(
                what="Custom test",
                so_what="Custom detection worked",
                why="Custom condition matched",
                implication="Test passed",
                strategy="Continue testing",
                confidence=0.95,
                level=UnderstandingLevel.STRATEGIC
            )
        
        rule = ReasoningRule(
            name="custom_rule",
            description="Custom test rule",
            level=UnderstandingLevel.STRATEGIC,
            condition=custom_condition,
            findings_builder=custom_finding,
            priority=200
        )
        
        self.reasoner.register_rule(rule)
        
        self.assertIn('custom_rule', [r.name for r in self.reasoner.rules])
        
        response_data = {
            'url': 'http://example.com/custom',
            'method': 'GET',
            'status_code': 200,
            'content_type': 'text/html',
            'content': 'custom content',
            'source': 'test'
        }
        
        insights = self.reasoner.observe_and_reason(response_data)
        custom_insights = [i for i in insights if 'custom' in i.content.lower()]
        self.assertGreater(len(custom_insights), 0)


class TestInsightType(unittest.TestCase):
    """洞察类型测试"""
    
    def test_insight_types_complete(self):
        """测试所有洞察类型"""
        expected_types = [
            'observation', 'pattern', 'inference', 
            'blocker', 'opportunity', 'strategy', 
            'warning', 'validation'
        ]
        
        actual_types = [t.value for t in InsightType]
        
        for expected in expected_types:
            self.assertIn(expected, actual_types)


class TestUnderstandingLevel(unittest.TestCase):
    """理解层级测试"""
    
    def test_understanding_levels(self):
        """测试理解层级"""
        levels = [l.value for l in UnderstandingLevel]
        
        self.assertIn('surface', levels)
        self.assertIn('context', levels)
        self.assertIn('causal', levels)
        self.assertIn('strategic', levels)


if __name__ == '__main__':
    unittest.main()
