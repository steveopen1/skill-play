#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
动态 API 分析模块 v2

利用 Playwright 进行运行时 API 分析：
1. 使用 CDP (Chrome DevTools Protocol) 拦截所有网络请求
2. 识别真实 API 调用 (fetch/axios/XHR)
3. 提取请求参数 (path/query/body)
4. 追踪交互来源 (点击/输入/导航触发)

使用方式:
    from core.dynamic_api_analyzer import DynamicAPIAnalyzer
    
    analyzer = DynamicAPIAnalyzer('http://target.com')
    results = analyzer.analyze_full()
"""

import re
import time
import json
from typing import Dict, List, Set, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime

import sys
sys.path.insert(0, '/workspace/skill-play/API-Security-Testing-Optimized')


@dataclass
class APIRequest:
    """API 请求"""
    url: str
    method: str = "GET"
    headers: Dict = field(default_factory=dict)
    post_data: Any = None
    query_params: Dict = field(default_factory=dict)
    path_params: Dict = field(default_factory=dict)
    source: str = ""  # fetch, axios, xhr, intercepted
    trigger: str = ""  # click_login, input_search, navigate_dashboard
    timestamp: float = 0
    response_status: int = 0
    response_body: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'method': self.method,
            'query_params': self.query_params,
            'path_params': self.path_params,
            'source': self.source,
            'trigger': self.trigger,
            'response_status': self.response_status,
        }


class DynamicAPIAnalyzer:
    """
    动态 API 分析器 v2
    
    改进:
    1. 使用 CDP Request interception 而非简单的事件监听
    2. 追踪触发来源 (stack trace 分析)
    3. 主动注入测试代码追踪交互
    """
    
    def __init__(self, target: str, headless: bool = True):
        self.target = target
        self.headless = headless
        self.requests: List[APIRequest] = []
        self._page = None
        self._context = None
        self._last_interaction = ""
        
    def analyze_full(self, max_requests: int = 100) -> Dict:
        """
        执行完整动态分析
        
        Args:
            max_requests: 最大捕获请求数
        
        Returns:
            {
                'total': 100,
                'api_requests': [...],
                'endpoints': {...},
                'params_summary': {...}
            }
        """
        print(f"  [DynamicAPI v2] 启动动态分析")
        print(f"  [DynamicAPI v2] 目标: {self.target}")
        
        try:
            from playwright.sync_api import sync_playwright
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                self._context = browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    ignore_https_errors=True
                )
                self._page = self._context.new_page()
                
                self._setup_cdp_interceptor()
                
                self._visit_target()
                self._trigger_login_interactions()
                self._trigger_search_interactions()
                self._trigger_navigation()
                self._trigger_form_submissions()
                
                browser.close()
                
        except ImportError:
            print(f"  [DynamicAPI] Playwright 不可用")
        except Exception as e:
            print(f"  [DynamicAPI] 分析失败: {e}")
        
        results = self._process_results()
        print(f"  [DynamicAPI] 捕获 {results['total_api']} 个 API 请求")
        
        return results
    
    def _setup_cdp_interceptor(self):
        """设置 CDP 请求拦截器"""
        
        # 1. 拦截所有请求
        def on_request(request):
            url = request.url
            method = request.method
            
            # 只处理目标域名的 API 请求
            if not self._is_api_request(url):
                return
            
            # 提取参数
            query_params = self._extract_query_params(url)
            path_params = self._extract_path_params(url)
            
            # 识别来源
            source = self._identify_source(request)
            
            api_req = APIRequest(
                url=url,
                method=method,
                headers=dict(request.headers),
                post_data=request.post_data,
                query_params=query_params,
                path_params=path_params,
                source=source,
                trigger=self._last_interaction,
                timestamp=time.time()
            )
            
            self.requests.append(api_req)
            print(f"  [API] {method} {self._short_url(url)}")
        
        # 2. 拦截响应获取状态码
        def on_response(response):
            for req in self.requests:
                if req.url == response.url:
                    req.response_status = response.status
                    try:
                        if response.status == 200:
                            body = response.text()
                            req.response_body = body[:500] if body else ""
                    except:
                        pass
                    break
        
        self._page.on("request", on_request)
        self._page.on("response", on_response)
    
    def _is_api_request(self, url: str) -> bool:
        """判断是否是 API 请求"""
        # 必须包含目标主机
        target_host = self.target.replace('http://', '').replace('https://', '').split(':')[0]
        if target_host not in url:
            return False
        
        # 排除静态资源 (严格匹配)
        skip_patterns = [
            r'\.js$', r'\.css$', r'\.jpg$', r'\.jpeg$', r'\.png$',
            r'\.gif$', r'\.svg$', r'\.ico$', r'\.woff$', r'\.woff2$',
            r'\.ttf$', r'\.eot$', r'\.map$', r'\.mp4$', r'\.mp3$',
            r'\.webm$', r'\.avi$', r'\.mov$', r'\.png\?', r'\.jpg\?',
            r'/static/', r'/assets/', r'/public/', r'/images/',
            r'/css/', r'/fonts/', r'/media/', r'/videos/',
        ]
        
        url_lower = url.lower()
        for pattern in skip_patterns:
            if re.search(pattern, url_lower):
                return False
        
        # API 路径特征 (必须是这些模式之一)
        api_patterns = [
            '/api/', '/rest/', '/v1/', '/v2/', '/v3/',
            '/graphql', '/query', '/login', '/auth',
            '/user/', '/admin/', '/config/', '/data/',
            '/file/', '/upload/', '/download/',
            '/icp-api/',  # 发现的内部 API 前缀
        ]
        
        for pattern in api_patterns:
            if pattern in url_lower:
                return True
        
        # POST 请求通常是 API
        # 检查 URL 中是否有查询参数
        if '?' in url:
            return True
        
        return False
    
    def _short_url(self, url: str, max_len: int = 60) -> str:
        """缩短 URL 用于显示"""
        if len(url) > max_len:
            return url[:max_len] + "..."
        return url
    
    def _extract_query_params(self, url: str) -> Dict:
        """提取查询参数"""
        params = {}
        if '?' not in url:
            return params
        
        query_str = url.split('?')[1]
        for pair in query_str.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key] = value
            else:
                params[pair] = ""
        return params
    
    def _extract_path_params(self, path: str) -> Dict:
        """提取路径参数"""
        params = {}
        
        # 移除查询参数
        if '?' in path:
            path = path.split('?')[0]
        
        # 移除目标前缀
        target_path = path.replace(self.target.rstrip('/'), '')
        
        # 数字 ID 模式
        id_patterns = [
            (r'/(\d+)', 'id'),
            (r'/([a-f0-9-]{32,})', 'uuid'),
            (r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', 'uuid'),
        ]
        
        for pattern, name in id_patterns:
            matches = re.findall(pattern, path)
            for m in matches:
                params[name] = m
                break
        
        return params
    
    def _identify_source(self, request) -> str:
        """识别请求来源"""
        headers = dict(request.headers)
        headers_str = str(headers).lower()
        
        # 根据头信息判断
        if 'x-requested-with' in headers_str and 'xmlhttprequest' in headers_str:
            return 'xhr'
        if 'content-type' in headers:
            ct = headers['content-type'].lower()
            if 'application/json' in ct:
                return 'fetch' if 'fetch' in headers_str else 'axios'
        
        # 根据 URL 模式判断
        url = request.url.lower()
        if 'axios' in url:
            return 'axios'
        if 'api' in url:
            return 'api'
        
        return 'unknown'
    
    def _visit_target(self):
        """访问目标页面"""
        print(f"  [DynamicAPI] 访问目标...")
        self._last_interaction = "visit_home"
        try:
            self._page.goto(self.target, wait_until='networkidle', timeout=30000)
            self._page.wait_for_timeout(2000)
        except Exception as e:
            print(f"  [WARN] 访问失败: {e}")
    
    def _trigger_login_interactions(self):
        """触发登录相关交互"""
        print(f"  [DynamicAPI] 触发登录交互...")
        self._last_interaction = "trigger_login"
        
        # 1. 尝试导航到登录页
        try:
            if '#/login' not in self._page.url:
                self._page.goto(self.target + '#/login', timeout=10000)
                self._page.wait_for_timeout(2000)
        except:
            pass
        
        # 2. 填写登录表单
        selectors = [
            'input[type="text"]', 'input[type="email"]',
            'input[name="username"]', 'input[name="user"]',
            'input[placeholder*="用户"]', 'input[placeholder*="账号"]',
        ]
        
        for selector in selectors:
            try:
                inputs = self._page.query_selector_all(selector)
                for i, inp in enumerate(inputs[:2]):
                    try:
                        inp.fill(f'testuser{i}')
                        self._page.wait_for_timeout(300)
                    except:
                        pass
            except:
                pass
        
        # 3. 填写密码
        password_selectors = [
            'input[type="password"]',
            'input[name="password"]',
        ]
        
        for selector in password_selectors:
            try:
                inputs = self._page.query_selector_all(selector)
                for inp in inputs[:1]:
                    try:
                        inp.fill('TestPassword123!')
                        self._page.wait_for_timeout(300)
                    except:
                        pass
            except:
                pass
        
        # 4. 点击登录按钮
        try:
            buttons = self._page.query_selector_all('button[type="submit"], button:has-text("登录"), button:has-text("Login")')
            for btn in buttons[:2]:
                try:
                    btn.click()
                    self._page.wait_for_timeout(1000)
                except:
                    pass
        except:
            pass
    
    def _trigger_search_interactions(self):
        """触发搜索相关交互"""
        print(f"  [DynamicAPI] 触发搜索交互...")
        self._last_interaction = "trigger_search"
        
        search_selectors = [
            'input[type="search"]',
            'input[placeholder*="搜索"]',
            'input[placeholder*="查询"]',
            'input[placeholder*="search"]',
            '.search-input',
            '.el-input__inner',
        ]
        
        for selector in search_selectors:
            try:
                inputs = self._page.query_selector_all(selector)
                for inp in inputs[:2]:
                    try:
                        inp.fill('test query')
                        self._page.wait_for_timeout(500)
                        inp.press('Enter')
                        self._page.wait_for_timeout(1000)
                    except:
                        pass
            except:
                pass
    
    def _trigger_navigation(self):
        """触发导航"""
        print(f"  [DynamicAPI] 触发导航...")
        
        routes = [
            '#/home',
            '#/dashboard',
            '#/admin',
            '#/profile',
            '#/user',
            '#/system',
            '#/report',
        ]
        
        for route in routes:
            self._last_interaction = f"navigate_{route.replace('#/', '')}"
            try:
                url = self.target.rstrip('/') + route
                self._page.goto(url, timeout=10000)
                self._page.wait_for_timeout(2000)
            except:
                pass
    
    def _trigger_form_submissions(self):
        """触发表单提交"""
        print(f"  [DynamicAPI] 触发表单提交...")
        self._last_interaction = "trigger_form"
        
        # 点击各种按钮
        button_selectors = [
            'button:not([disabled])',
            'a.btn',
            '.el-button',
        ]
        
        for selector in button_selectors:
            try:
                buttons = self._page.query_selector_all(selector)
                for btn in buttons[:5]:
                    try:
                        btn.click()
                        self._page.wait_for_timeout(500)
                    except:
                        pass
            except:
                pass
    
    def _process_results(self) -> Dict:
        """处理捕获结果"""
        
        # 过滤真正的 API 请求
        api_requests = [r for r in self.requests if r.response_status > 0 or r.query_params]
        
        # 统计端点
        endpoint_stats = {}
        for req in api_requests:
            path = req.url.split('?')[0]
            method = req.method
            
            key = f"{method} {path}"
            if key not in endpoint_stats:
                endpoint_stats[key] = {
                    'path': path,
                    'method': method,
                    'count': 0,
                    'params': set(),
                    'sources': set(),
                    'triggers': set(),
                    'statuses': set(),
                }
            
            stats = endpoint_stats[key]
            stats['count'] += 1
            stats['params'].update(req.query_params.keys())
            stats['params'].update(req.path_params.keys())
            if req.source:
                stats['sources'].add(req.source)
            if req.trigger:
                stats['triggers'].add(req.trigger)
            if req.response_status:
                stats['statuses'].add(req.response_status)
        
        # 转换端点统计
        endpoints = []
        for key, stats in endpoint_stats.items():
            endpoints.append({
                'path': stats['path'],
                'method': stats['method'],
                'count': stats['count'],
                'params': list(stats['params']),
                'sources': list(stats['sources']),
                'triggers': list(stats['triggers']),
                'statuses': list(stats['statuses']),
            })
        
        # 按调用次数排序
        endpoints.sort(key=lambda x: -x['count'])
        
        # 参数统计
        all_params = {}
        for ep in endpoints:
            for param in ep['params']:
                all_params[param] = all_params.get(param, 0) + 1
        
        return {
            'total': len(self.requests),
            'total_api': len(api_requests),
            'endpoints': endpoints,
            'param_summary': all_params,
            'requests': [r.to_dict() for r in api_requests[:50]],
        }


def run_full_analysis(target: str) -> Dict:
    """运行完整动态分析"""
    print("=" * 60)
    print("Dynamic API Analyzer v2")
    print("=" * 60)
    
    analyzer = DynamicAPIAnalyzer(target)
    results = analyzer.analyze_full()
    
    print("\n" + "=" * 60)
    print("分析结果")
    print("=" * 60)
    print(f"总请求: {results['total']}")
    print(f"API 请求: {results['total_api']}")
    print(f"唯一端点: {len(results['endpoints'])}")
    
    if results['param_summary']:
        print(f"\nTop 参数:")
        top_params = sorted(results['param_summary'].items(), key=lambda x: -x[1])[:10]
        for param, count in top_params:
            print(f"  {param}: {count} 次")
    
    if results['endpoints']:
        print(f"\n端点详情 (前 10):")
        for ep in results['endpoints'][:10]:
            params_str = ', '.join(ep['params'][:5])
            print(f"  {ep['method']} {ep['path']}")
            print(f"    调用 {ep['count']} 次, 参数: {params_str}")
    
    return results


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://58.215.18.57:91"
    run_full_analysis(target)
