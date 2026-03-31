#!/usr/bin/env python3
"""
单元测试 - StrategyPool
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.strategy_pool import (
    StrategyPool, Strategy, Strategist, StrategyContext,
    Action, Condition, StrategyState, StrategyMetrics,
    create_strategy_pool, create_strategist
)


class TestStrategyPool(unittest.TestCase):
    """策略池测试"""
    
    def setUp(self):
        self.pool = create_strategy_pool()
    
    def test_strategy_pool_creation(self):
        """测试策略池创建"""
        self.assertIsNotNone(self.pool)
        self.assertIsInstance(self.pool.strategies, dict)
        self.assertGreater(len(self.pool.strategies), 0)
    
    def test_default_strategies(self):
        """测试默认策略"""
        expected_ids = [
            'default', 'waf_detected', 'spa_fallback',
            'internal_address', 'high_value_endpoint',
            'auth_testing', 'rate_limited', 'sensitive_operation'
        ]
        
        for strategy_id in expected_ids:
            self.assertIn(strategy_id, self.pool.strategies)
    
    def test_get_strategy(self):
        """测试获取策略"""
        strategy = self.pool.get_strategy('default')
        self.assertIsNotNone(strategy)
        self.assertEqual(strategy.id, 'default')
    
    def test_select_strategy_default(self):
        """测试默认策略选择"""
        context = StrategyContext({})
        strategy = self.pool.select_strategy(context)
        
        self.assertIsNotNone(strategy)
    
    def test_select_strategy_waf(self):
        """测试 WAF 检测场景策略选择"""
        context = StrategyContext({
            'waf_detected': 'aliyun',
            'insight_types': ['waf_detected']
        })
        
        strategy = self.pool.select_strategy(context)
        
        self.assertEqual(strategy.id, 'waf_detected')
    
    def test_select_strategy_spa(self):
        """测试 SPA 场景策略选择"""
        context = StrategyContext({
            'is_spa': True,
            'insight_types': ['spa_fallback']
        })
        
        strategy = self.pool.select_strategy(context)
        
        self.assertEqual(strategy.id, 'spa_fallback')
    
    def test_select_strategy_high_value(self):
        """测试高价值端点场景策略选择"""
        context = StrategyContext({
            'endpoint_score': 9,
            'insight_types': []
        })
        
        strategy = self.pool.select_strategy(context)
        
        self.assertEqual(strategy.id, 'high_value_endpoint')
    
    def test_select_strategy_internal_ip(self):
        """测试内网地址场景策略选择"""
        context = StrategyContext({
            'has_internal_ips': True,
            'internal_ips': {'10.0.0.1'},
            'insight_types': []
        })
        
        strategy = self.pool.select_strategy(context)
        
        self.assertEqual(strategy.id, 'internal_address')
    
    def test_select_strategy_rate_limited(self):
        """测试限速场景策略选择"""
        context = StrategyContext({
            'network_status': 'rate_limited',
            'insight_types': []
        })
        
        strategy = self.pool.select_strategy(context)
        
        self.assertEqual(strategy.id, 'rate_limited')
    
    def test_select_multiple(self):
        """测试选择多个策略"""
        context = StrategyContext({
            'is_spa': True,
            'waf_detected': 'aliyun'
        })
        
        strategies = self.pool.select_multiple(context, max_strategies=3)
        
        self.assertLessEqual(len(strategies), 3)
        self.assertGreater(len(strategies), 0)
    
    def test_strategy_can_activate(self):
        """测试策略激活条件"""
        strategy = self.pool.get_strategy('waf_detected')
        
        context_with_waf = StrategyContext({'waf_detected': 'aliyun'})
        self.assertTrue(strategy.can_activate(context_with_waf))
        
        context_without_waf = StrategyContext({'waf_detected': None})
        self.assertFalse(strategy.can_activate(context_without_waf))
    
    def test_record_outcome(self):
        """测试记录策略结果"""
        self.pool.record_outcome('default', success=True, effectiveness=0.8)
        
        strategy = self.pool.get_strategy('default')
        self.assertEqual(strategy.metrics.total_executions, 1)
        self.assertEqual(strategy.metrics.success_count, 1)


class TestCondition(unittest.TestCase):
    """条件测试"""
    
    def test_condition_evaluation(self):
        """测试条件评估"""
        condition = Condition(
            type='insight_type',
            operator='contains',
            value='waf_detected'
        )
        
        context_with = StrategyContext({'insight_types': ['waf_detected', 'spa_fallback']})
        self.assertTrue(condition.evaluate(context_with))
        
        context_without = StrategyContext({'insight_types': ['spa_fallback']})
        self.assertFalse(condition.evaluate(context_without))
    
    def test_condition_endpoint_score(self):
        """测试端点评分条件"""
        condition = Condition(
            type='endpoint_score',
            operator='greater_than',
            value=5
        )
        
        context_high = StrategyContext({'endpoint_score': 8})
        self.assertTrue(condition.evaluate(context_high))
        
        context_low = StrategyContext({'endpoint_score': 3})
        self.assertFalse(condition.evaluate(context_low))
    
    def test_condition_network_status(self):
        """测试网络状态条件"""
        condition = Condition(
            type='network_status',
            operator='in',
            value=['rate_limited', 'blocked']
        )
        
        context_limited = StrategyContext({'network_status': 'rate_limited'})
        self.assertTrue(condition.evaluate(context_limited))
        
        context_normal = StrategyContext({'network_status': 'normal'})
        self.assertFalse(condition.evaluate(context_normal))


class TestStrategyMetrics(unittest.TestCase):
    """策略指标测试"""
    
    def test_record_execution_success(self):
        """测试记录成功执行"""
        metrics = StrategyMetrics()
        
        metrics.record_execution(success=True, effectiveness=0.9)
        
        self.assertEqual(metrics.total_executions, 1)
        self.assertEqual(metrics.success_count, 1)
        self.assertEqual(metrics.avg_effectiveness, 0.9)
    
    def test_record_execution_failure(self):
        """测试记录失败执行"""
        metrics = StrategyMetrics()
        
        metrics.record_execution(success=False, effectiveness=0.2)
        
        self.assertEqual(metrics.total_executions, 1)
        self.assertEqual(metrics.failure_count, 1)
    
    def test_average_effectiveness(self):
        """测试平均效果计算"""
        metrics = StrategyMetrics()
        
        metrics.record_execution(success=True, effectiveness=0.8)
        metrics.record_execution(success=True, effectiveness=0.6)
        
        self.assertAlmostEqual(metrics.avg_effectiveness, 0.7)


class TestStrategist(unittest.TestCase):
    """策略师测试"""
    
    def setUp(self):
        self.strategist = create_strategist()
    
    def test_strategist_creation(self):
        """测试策略师创建"""
        self.assertIsNotNone(self.strategist)
        self.assertIsNotNone(self.strategist.strategy_pool)
    
    def test_create_strategy_plan(self):
        """测试创建策略计划"""
        context = StrategyContext({'is_spa': True})
        
        plan = self.strategist.create_strategy_plan(context)
        
        self.assertIsNotNone(plan)
        self.assertIsNotNone(plan.primary_strategy)
        self.assertIsNotNone(plan.fallback_strategy)
    
    def test_evaluate_effectiveness(self):
        """测试效果评估"""
        strategy = Strategy(
            id='test',
            name='Test Strategy',
            description='Test',
            priority=0
        )
        
        results = {
            'vulnerabilities_found': 5,
            'coverage': 0.8,
            'execution_time': 100,
            'false_positive_rate': 0.1
        }
        
        effectiveness = self.strategist.evaluate_effectiveness(strategy, results)
        
        self.assertGreater(effectiveness, 0)
        self.assertLessEqual(effectiveness, 1)


if __name__ == '__main__':
    unittest.main()
