#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
动态 API 分析模块

利用 Playwright 的 CDP (Chrome DevTools Protocol) 进行动态 API 分析：
1. Hook 网络请求，捕获真实 API 调用
2. 主动触发 SPA 中的交互操作
3. 拦截 fetch/axios/XHR 请求
4. 分析请求参数和响应

使用方式:
    from core.dynamic_api_analyzer import DynamicAPIAnalyzer
    
    analyzer = DynamicAPIAnalyzer('http://target.com')
    results = analyzer.analyze()
"""

import re
import time
import json
from typing import Dict, List, Set, Optional, Any, Callable
from dataclasses import dataclass, field

import sys
sys.path.insert(0, '/workspace/skill-play/API-Security-Testing-Optimized')


@dataclass
class CapturedRequest:
    """捕获的 API 请求"""
    url: str
    method: str = "GET"
    headers: Dict = field(default_factory=dict)
    post_data: Any = None
    query_params: Dict = field(default_factory=dict)
    path_params: Dict = field(default_factory=dict)
    source: str = ""  # fetch, axios, xhr, xhr intercepted
    timestamp: float = 0
    
    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'post_data': self.post_data,
            'query_params': self.query_params,
            'path_params': self.path_params,
            'source': self.source,
        }


@dataclass
class EndpointWithParams:
    """带参数的端点"""
    path: str
    method: str
    params: Dict[str, Any]
    request: CapturedRequest = None


class DynamicAPIAnalyzer:
    """
    动态 API 分析器
    
    使用 Playwright 进行运行时 API 调用捕获
    """
    
    def __init__(self, target: str, headless: bool = True):
        self.target = target
        self.headless = headless
        self.captured_requests: List[CapturedRequest] = []
        self._page = None
        self._browser = None
    
    def analyze(
        self,
        interactions: List[str] = None,
        wait_time: int = 2
    ) -> Dict:
        """
        执行动态分析
        
        Args:
            interactions: 要触发的交互操作列表，如 ['click', 'input', 'navigate']
            wait_time: 等待网络请求的时间（秒）
        
        Returns:
            分析结果字典
        """
        print(f"  [DynamicAPI] 启动动态分析，目标: {self.target}")
        
        try:
            from playwright.sync_api import sync_playwright
            
            with sync_playwright() as p:
                self._browser = p.chromium.launch(headless=self.headless)
                context = self._browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    ignore_https_errors=True
                )
                self._page = context.new_page()
                
                # 设置请求拦截
                self._setup_interceptors()
                
                # 1. 访问目标页面
                print(f"  [DynamicAPI] 访问目标页面...")
                self._page.goto(self.target, wait_until='networkidle', timeout=30000)
                self._page.wait_for_timeout(wait_time * 1000)
                
                # 2. 执行交互操作触发 API 调用
                if interactions:
                    for action in interactions:
                        self._execute_interaction(action)
                
                # 3. 触发 SPA 中的常见操作
                print(f"  [DynamicAPI] 触发 SPA 交互...")
                self._trigger_spa_interactions()
                
                # 4. 导航到不同路由
                print(f"  [DynamicAPI] 测试路由导航...")
                self._test_routes()
                
                self._browser.close()
                
        except ImportError:
            print(f"  [DynamicAPI] Playwright 不可用")
        except Exception as e:
            print(f"  [DynamicAPI] 分析失败: {e}")
        
        # 处理捕获的请求
        results = self._process_results()
        print(f"  [DynamicAPI] 捕获 {len(self.captured_requests)} 个 API 请求")
        
        return results
    
    def _setup_interceptors(self):
        """设置请求拦截器"""
        
        def handle_request(request):
            """拦截所有请求"""
            url = request.url
            method = request.method
            
            # 只处理目标域名的 API 请求
            if self._is_api_url(url):
                # 提取查询参数
                query_params = self._extract_query_params(url)
                
                # 判断请求来源
                source = self._identify_source(request)
                
                captured = CapturedRequest(
                    url=url,
                    method=method,
                    headers=dict(request.headers),
                    post_data=request.post_data,
                    query_params=query_params,
                    source=source,
                    timestamp=time.time()
                )
                
                self.captured_requests.append(captured)
        
        def handle_response(response):
            """拦截响应"""
            pass
        
        self._page.on("request", handle_request)
        self._page.on("response", handle_response)
    
    def _is_api_url(self, url: str) -> bool:
        """判断是否是 API URL"""
        # 目标域名
        target_host = self.target.replace('http://', '').replace('https://', '').split('/')[0]
        
        # 必须包含目标主机
        if target_host not in url:
            return False
        
        # 排除静态资源
        skip_extensions = ['.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf']
        for ext in skip_extensions:
            if url.endswith(ext):
                return False
        
        # API 路径特征
        api_patterns = ['/api/', '/rest/', '/v1/', '/v2/', '/graphql', '/query', '/login', '/auth']
        for pattern in api_patterns:
            if pattern in url.lower():
                return True
        
        return False
    
    def _extract_query_params(self, url: str) -> Dict:
        """从 URL 中提取查询参数"""
        params = {}
        if '?' in url:
            query_str = url.split('?')[1]
            for pair in query_str.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key] = value
        return params
    
    def _identify_source(self, request) -> str:
        """识别请求来源"""
        headers = dict(request.headers)
        
        # 检查特定头
        if 'x-requested-with' in headers:
            return 'xhr'
        if 'content-type' in headers:
            ct = headers['content-type'].lower()
            if 'application/json' in ct:
                return 'fetch' if 'fetch' in str(request.headers).lower() else 'xhr'
        
        # 根据 URL 模式判断
        url = request.url.lower()
        if 'axios' in url or 'api' in url:
            return 'axios'
        
        return 'unknown'
    
    def _execute_interaction(self, action: str):
        """执行交互操作"""
        try:
            if action == 'click':
                # 点击所有可点击元素
                for element in self._page.query_selector_all('button, a, [onclick]'):
                    try:
                        element.click()
                        self._page.wait_for_timeout(500)
                    except:
                        pass
            
            elif action == 'input':
                # 填写表单
                for input_el in self._page.query_selector_all('input, textarea'):
                    try:
                        input_el.fill('test')
                    except:
                        pass
            
            elif action == 'scroll':
                self._page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
                self._page.wait_for_timeout(1000)
                self._page.evaluate('window.scrollTo(0, 0)')
            
            elif action.startswith('goto:'):
                # 导航到指定路由
                route = action.replace('goto:', '')
                self._page.goto(self.target + route, timeout=10000)
                self._page.wait_for_timeout(2000)
            
        except Exception as e:
            pass
    
    def _trigger_spa_interactions(self):
        """触发 SPA 中的常见交互"""
        
        # 1. 尝试点击登录相关的按钮/链接
        login_selectors = [
            'button:has-text("登录")',
            'button:has-text("Login")',
            'a:has-text("登录")',
            '[type="submit"]',
        ]
        
        for selector in login_selectors:
            try:
                elements = self._page.query_selector_all(selector)
                for el in elements[:3]:  # 最多尝试3个
                    try:
                        el.click()
                        self._page.wait_for_timeout(1000)
                    except:
                        pass
            except:
                pass
        
        # 2. 尝试填写表单
        try:
            inputs = self._page.query_selector_all('input')
            for i, inp in enumerate(inputs[:5]):
                try:
                    inp.fill(f'test{i}')
                except:
                    pass
        except:
            pass
        
        # 3. 触发搜索框输入
        try:
            search_inputs = self._page.query_selector_all('input[type="search"], input[placeholder*="搜索"], input[placeholder*="search"]')
            for inp in search_inputs[:2]:
                try:
                    inp.fill('test')
                    inp.press('Enter')
                    self._page.wait_for_timeout(1000)
                except:
                    pass
        except:
            pass
    
    def _test_routes(self):
        """测试不同的 SPA 路由"""
        routes = [
            '#/login',
            '#/home',
            '#/dashboard',
            '#/admin',
            '#/profile',
        ]
        
        for route in routes:
            try:
                url = self.target.rstrip('/') + route
                self._page.goto(url, timeout=10000)
                self._page.wait_for_timeout(2000)
            except:
                pass
    
    def _process_results(self) -> Dict:
        """处理捕获结果"""
        
        # 提取端点和参数
        endpoints = []
        seen_urls = set()
        
        for req in self.captured_requests:
            if req.url in seen_urls:
                continue
            seen_urls.add(req.url)
            
            # 提取路径（去掉查询参数）
            path = req.url.split('?')[0].replace(self.target.rstrip('/'), '')
            
            # 提取路径参数
            path_params = self._extract_path_params(path)
            
            endpoint = {
                'path': path,
                'method': req.method,
                'params': {**req.query_params, **path_params},
                'source': req.source,
                'url': req.url,
            }
            endpoints.append(endpoint)
        
        return {
            'total_requests': len(self.captured_requests),
            'unique_endpoints': len(endpoints),
            'endpoints': endpoints,
            'requests': [r.to_dict() for r in self.captured_requests],
        }
    
    def _extract_path_params(self, path: str) -> Dict:
        """从路径中提取参数"""
        params = {}
        
        # 常见 RESTful 模式
        patterns = [
            (r'/(\d+)', 'id'),
            (r'/([a-f0-9-]{36})', 'uuid'),
            (r'/([a-zA-Z0-9_]+)/([a-zA-Z0-9_]+)', None),  # 分组但不提取
        ]
        
        return params
    
    def get_endpoints_with_params(self) -> List[EndpointWithParams]:
        """获取带参数的端点列表"""
        results = self.analyze()
        
        endpoints = []
        for ep in results.get('endpoints', []):
            if ep.get('params'):
                endpoint = EndpointWithParams(
                    path=ep['path'],
                    method=ep['method'],
                    params=ep['params'],
                )
                endpoints.append(endpoint)
        
        return endpoints


def run_dynamic_analysis(target: str, interactions: List[str] = None) -> Dict:
    """
    运行动态 API 分析
    
    Args:
        target: 目标 URL
        interactions: 要执行的交互操作列表
    
    Returns:
        分析结果
    """
    print(f"[DynamicAPI] 开始动态分析: {target}")
    
    analyzer = DynamicAPIAnalyzer(target)
    results = analyzer.analyze(interactions=interactions)
    
    print(f"[DynamicAPI] 分析完成:")
    print(f"  - 总请求: {results.get('total_requests', 0)}")
    print(f"  - 唯一端点: {results.get('unique_endpoints', 0)}")
    
    return results


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "http://58.215.18.57:91"
    
    results = run_dynamic_analysis(target)
    print(json.dumps(results, indent=2, default=str))
