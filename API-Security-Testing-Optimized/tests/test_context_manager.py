#!/usr/bin/env python3
"""
单元测试 - ContextManager
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.context_manager import (
    ContextManager, GlobalContext, TechStackContext,
    NetworkContext, SecurityContext, ContentContext,
    Endpoint, TestPhase, RateLimitStatus, ExposureLevel,
    DataClassification, ProxyConfig,
    create_context_manager
)


class TestContextManager(unittest.TestCase):
    """上下文管理器测试"""
    
    def setUp(self):
        self.cm = create_context_manager("http://example.com")
    
    def test_context_manager_creation(self):
        """测试上下文管理器创建"""
        self.assertIsNotNone(self.cm)
        self.assertEqual(self.cm.context.target_url, "http://example.com")
        self.assertEqual(self.cm.context.current_phase, TestPhase.INIT)
    
    def test_tech_stack_update(self):
        """测试技术栈更新"""
        self.cm.update_tech_stack({
            'frontend': {'vue', 'webpack'},
            'backend': {'spring'}
        })
        
        self.assertIn('vue', self.cm.context.tech_stack.frontend)
        self.assertIn('spring', self.cm.context.tech_stack.backend)
    
    def test_waf_setting(self):
        """测试 WAF 设置"""
        self.cm.set_waf("aliyun", confidence=0.9)
        
        self.assertEqual(self.cm.context.tech_stack.waf, "aliyun")
        self.assertEqual(self.cm.context.tech_stack.confidence.get('waf'), 0.9)
    
    def test_spa_mode(self):
        """测试 SPA 模式设置"""
        self.cm.set_spa_mode(True, fallback_size=678)
        
        self.assertTrue(self.cm.context.content.is_spa)
        self.assertEqual(self.cm.context.content.spa_fallback_size, 678)
    
    def test_internal_address_marking(self):
        """测试内网地址标记"""
        self.cm.mark_internal_address("10.0.0.1", source="js_analysis")
        self.cm.mark_internal_address("192.168.1.1", source="response")
        
        self.assertIn("10.0.0.1", self.cm.context.content.internal_ips)
        self.assertIn("192.168.1.1", self.cm.context.content.internal_ips)
    
    def test_swagger_url_addition(self):
        """测试 Swagger URL 添加"""
        self.cm.add_swagger_url("http://example.com/api-docs")
        self.cm.add_swagger_url("http://example.com/swagger.json")
        
        self.assertEqual(len(self.cm.context.content.swagger_urls), 2)
        self.assertTrue(self.cm.context.content.has_api_docs)
    
    def test_endpoint_discovery(self):
        """测试端点发现"""
        endpoint = Endpoint(
            path="/api/users",
            method="GET",
            score=8,
            is_high_value=True
        )
        
        self.cm.add_discovered_endpoint(endpoint)
        
        self.assertEqual(len(self.cm.context.discovered_endpoints), 1)
        
        high_value = self.cm.get_high_value_endpoints()
        self.assertEqual(len(high_value), 1)
    
    def test_network_status(self):
        """测试网络状态更新"""
        self.cm.update_network_status(True)
        self.assertTrue(self.cm.context.network.is_reachable)
        self.assertEqual(self.cm.context.network.rate_limit_status, RateLimitStatus.NORMAL)
        
        self.cm.update_network_status(False, reason="Connection timeout")
        self.assertFalse(self.cm.context.network.is_reachable)
    
    def test_rate_limit_tracking(self):
        """测试限速追踪"""
        for i in range(3):
            self.cm.update_network_status(False)
        
        self.assertEqual(self.cm.context.network.consecutive_failures, 3)
        self.assertEqual(self.cm.context.network.rate_limit_status, RateLimitStatus.RATE_LIMITED)
        
        for i in range(2):
            self.cm.update_network_status(False)
        
        self.assertEqual(self.cm.context.network.rate_limit_status, RateLimitStatus.BLOCKED)
    
    def test_phase_setting(self):
        """测试阶段设置"""
        self.cm.set_phase(TestPhase.DISCOVERY)
        self.assertEqual(self.cm.context.current_phase, TestPhase.DISCOVERY)
        
        self.cm.set_phase(TestPhase.TESTING)
        self.assertEqual(self.cm.context.current_phase, TestPhase.TESTING)
    
    def test_user_preferences(self):
        """测试用户偏好"""
        self.cm.set_user_preference("theme", "dark")
        self.cm.set_user_preference("language", "en")
        
        self.assertEqual(self.cm.get_user_preference("theme"), "dark")
        self.assertEqual(self.cm.get_user_preference("language"), "en")
        self.assertIsNone(self.cm.get_user_preference("nonexistent"))
        self.assertEqual(self.cm.get_user_preference("nonexistent", "default"), "default")
    
    def test_context_export(self):
        """测试上下文导出"""
        exported = self.cm.export_context()
        
        self.assertIn('target_url', exported)
        self.assertIn('tech_stack', exported)
        self.assertIn('network', exported)
        self.assertIn('content', exported)
    
    def test_context_summary(self):
        """测试上下文摘要"""
        summary = self.cm.get_summary()
        
        self.assertIn('target_url', summary)
        self.assertIn('phase', summary)
        self.assertIn('tech_stack', summary)
        self.assertIn('network', summary)
        self.assertIn('endpoints', summary)
    
    def test_needs_proxy(self):
        """测试代理需求判断"""
        self.assertFalse(self.cm.needs_proxy())
        
        self.cm.mark_internal_address("10.0.0.1")
        self.assertTrue(self.cm.needs_proxy())
    
    def test_is_rate_limited(self):
        """测试限速判断"""
        self.assertFalse(self.cm.is_rate_limited())
        
        for i in range(5):
            self.cm.update_network_status(False)
        
        self.assertTrue(self.cm.is_rate_limited())
    
    def test_get_current_rate_limit(self):
        """测试当前速率限制获取"""
        rate = self.cm.get_current_rate_limit()
        self.assertEqual(rate, 10)
        
        for i in range(3):
            self.cm.update_network_status(False)
        
        rate = self.cm.get_current_rate_limit()
        self.assertEqual(rate, 1)


class TestEndpoint(unittest.TestCase):
    """端点测试"""
    
    def test_endpoint_creation(self):
        """测试端点创建"""
        endpoint = Endpoint(
            path="/api/test",
            method="POST",
            score=5
        )
        
        self.assertEqual(endpoint.path, "/api/test")
        self.assertEqual(endpoint.method, "POST")
        self.assertEqual(endpoint.score, 5)
        self.assertFalse(endpoint.is_high_value)
    
    def test_endpoint_to_dict(self):
        """测试端点序列化"""
        endpoint = Endpoint(
            path="/api/test",
            method="GET",
            score=8,
            is_high_value=True
        )
        
        d = endpoint.to_dict()
        
        self.assertEqual(d['path'], "/api/test")
        self.assertEqual(d['method'], "GET")
        self.assertEqual(d['score'], 8)
        self.assertTrue(d['is_high_value'])


class TestProxyConfig(unittest.TestCase):
    """代理配置测试"""
    
    def test_proxy_config_creation(self):
        """测试代理配置创建"""
        proxy = ProxyConfig(
            http_proxy="http://proxy:8080",
            https_proxy="https://proxy:8080"
        )
        
        self.assertEqual(proxy.http_proxy, "http://proxy:8080")
        self.assertEqual(proxy.https_proxy, "https://proxy:8080")


if __name__ == '__main__':
    unittest.main()
