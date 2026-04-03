#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API 参数 Hook 模块

使用 Playwright 在浏览器中 Hook API 调用，获取真实参数：
1. Hook XMLHttpRequest / Fetch / axios
2. 记录每次 API 调用的 URL、方法、参数
3. 分析参数语义（如 password、username 等）
4. 识别潜在的安全测试点

使用方式:
    from core.api_interceptor import APIInterceptor
    
    interceptor = APIInterceptor('http://target.com')
    results = interceptor.hook_all_apis()
"""

import re
import sys
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

sys.path.insert(0, '/workspace/skill-play/API-Security-Testing-Optimized')


@dataclass
class HookedAPI:
    """Hook 到的 API 调用"""
    url: str
    method: str
    params: Dict[str, Any] = field(default_factory=dict)
    body: Any = None
    function_name: str = ""
    stack_trace: str = ""
    timestamp: float = 0
    
    # 分析结果
    semantic_type: str = ""  # login, reset_password, user_query, etc.
    is_sensitive: bool = False
    test_vectors: List[Dict] = field(default_factory=list)


class APIInterceptor:
    """
    API 参数 Hook 器
    
    在浏览器中注入 JavaScript 代码来 Hook 所有 API 调用
    """
    
    def __init__(self, target: str, headless: bool = True):
        self.target = target
        self.headless = headless
        self.hooked_apis: List[HookedAPI] = []
        self._page = None
        
        # 敏感操作模式
        self.sensitive_patterns = {
            'password': ['password', 'passwd', 'pwd', 'secret'],
            'auth': ['login', 'logout', 'auth', 'token', 'credential'],
            'user': ['user', 'profile', 'account', 'avatar'],
            'admin': ['admin', 'manage', 'system'],
            'reset': ['reset', 'forgot', 'recovery'],
            'delete': ['delete', 'remove', 'destroy'],
            'payment': ['pay', 'order', 'transaction', 'money'],
        }
        
        # 可测试的操作模式
        self.testable_patterns = [
            ('reset_password', 'password reset'),
            ('forgot_password', 'password recovery'),
            ('change_password', 'password change'),
            ('delete_account', 'account deletion'),
            ('modify_user', 'user modification'),
            ('admin_user', 'admin user management'),
        ]
    
    def hook_all_apis(self, interactions: List[str] = None) -> Dict:
        """
        Hook 所有 API 调用
        
        Args:
            interactions: 要执行的交互列表
        
        Returns:
            {
                'total': 100,
                'apis': [...],
                'sensitive': [...],
                'testable': [...],
                'test_vectors': [...]
            }
        """
        print(f"  [API Hook] 启动 Hook 器")
        print(f"  [API Hook] 目标: {self.target}")
        
        results = {'total': 0, 'apis': [], 'sensitive': [], 'testable': [], 'test_vectors': []}
        
        try:
            from playwright.sync_api import sync_playwright
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                context = browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    ignore_https_errors=True
                )
                
                hook_script = """
                (function() {
                    window.__API_CALLS__ = [];
                    var origFetch = window.fetch;
                    window.fetch = function() {
                        var args = arguments;
                        var url = args[0] || '';
                        var options = args[1] || {};
                        window.__API_CALLS__.push({
                            type: 'fetch',
                            method: (options.method || 'GET').toUpperCase(),
                            url: url
                        });
                        return origFetch.apply(window, args);
                    };
                    var OrigXHR = window.XMLHttpRequest;
                    window.XMLHttpRequest = function() {
                        var xhr = new OrigXHR();
                        xhr.open = function() {
                            this.__method = arguments[0];
                            this.__url = arguments[1];
                            return OrigXHR.prototype.open.apply(this, arguments);
                        };
                        xhr.send = function() {
                            this.__data = arguments[0];
                            var self = this;
                            this.addEventListener('load', function() {
                                window.__API_CALLS__.push({
                                    type: 'xhr',
                                    method: self.__method || 'GET',
                                    url: self.__url || '',
                                    data: self.__data || ''
                                });
                            });
                            return OrigXHR.prototype.send.apply(this, arguments);
                        };
                        return xhr;
                    };
                    console.log('[Hook] API Hook 已启动');
                })();
                """
                
                context.add_init_script(hook_script)
                
                page = context.new_page()
                self._page = page
                
                print(f"  [API Hook] 访问目标...")
                page.goto(self.target, wait_until='networkidle', timeout=30000)
                page.wait_for_timeout(3000)
                
                self._execute_interactions()
                
                results = self._process_results()
                
                browser.close()
                
        except Exception as e:
            print(f"  [API Hook] 失败: {e}")
        
        print(f"  [API Hook] 捕获 {results['total']} 个 API 调用")
        print(f"  [API Hook] 发现 {len(results.get('sensitive', []))} 个敏感操作")
        
        return results
    
    def _inject_hook_code(self):
        """注入 Hook 代码到页面"""
        
        # 简化的 Hook 代码
        hook_code = """
        (function() {
            if (window.__HOOKED__) return;
            window.__HOOKED__ = true;
            window.__API_CALLS__ = [];
            
            // Hook fetch
            var origFetch = window.fetch;
            window.fetch = function() {
                var args = arguments;
                var url = args[0] || '';
                var options = args[1] || {};
                
                window.__API_CALLS__.push({
                    type: 'fetch',
                    method: (options.method || 'GET').toUpperCase(),
                    url: url,
                    timestamp: Date.now()
                });
                
                return origFetch.apply(this, args);
            };
            
            // Hook XMLHttpRequest
            var origXHR = window.XMLHttpRequest;
            window.XMLHttpRequest = function() {
                var xhr = new origXHR();
                var origOpen = xhr.open;
                var origSend = xhr.send;
                
                xhr.open = function() {
                    this.__method = arguments[0];
                    this.__url = arguments[1];
                    return origOpen.apply(this, arguments);
                };
                
                xhr.send = function() {
                    this.__data = arguments[0];
                    var self = this;
                    this.addEventListener('load', function() {
                        window.__API_CALLS__.push({
                            type: 'xhr',
                            method: self.__method || 'GET',
                            url: self.__url || '',
                            data: self.__data || '',
                            timestamp: Date.now()
                        });
                    });
                    return origSend.apply(this, arguments);
                };
                
                return xhr;
            };
            
            console.log('[Hook] API Hook 已启动');
        })();
        """
        
        self._page.evaluate(hook_code)
    
    def _execute_interactions(self):
        """执行交互操作触发 API 调用"""
        print(f"  [API Hook] 执行交互...")
        
        # 1. 填写表单
        try:
            inputs = self._page.query_selector_all('input')
            for i, inp in enumerate(inputs[:10]):
                try:
                    inp.fill(f'test_value_{i}')
                    self._page.wait_for_timeout(300)
                except:
                    pass
        except:
            pass
        
        # 2. 点击按钮
        try:
            buttons = self._page.query_selector_all('button')
            for btn in buttons[:10]:
                try:
                    btn.click()
                    self._page.wait_for_timeout(500)
                except:
                    pass
        except:
            pass
        
        # 3. 导航
        routes = ['#/login', '#/home', '#/admin', '#/profile']
        for route in routes:
            try:
                self._page.goto(self.target + route, timeout=10000)
                self._page.wait_for_timeout(2000)
            except:
                pass
    
    def _process_results(self) -> Dict:
        """处理 Hook 结果"""
        
        # 获取 Hook 到的调用
        raw_calls = self._page.evaluate('window.__API_CALLS__ || []') if self._page else []
        
        apis = []
        sensitive = []
        testable = []
        test_vectors = []
        
        for call in raw_calls:
            url = call.get('url', '')
            method = call.get('method', 'GET').upper()
            data = call.get('data', {})
            params = call.get('params', {})
            
            # 只处理目标域名的 API
            target_host = self.target.replace('http://', '').replace('https://', '').split('/')[0]
            if target_host not in url:
                continue
            
            # 提取路径
            path = url.replace(f'http://{target_host}', '').split('?')[0]
            
            # 解析参数
            parsed_params = self._parse_params(data, params)
            
            # 创建 HookedAPI 对象
            api = HookedAPI(
                url=url,
                method=method,
                params=parsed_params,
                body=data,
                semantic_type=self._infer_semantic_type(path, method)
            )
            
            # 检测敏感操作
            if self._is_sensitive_operation(path, method):
                api.is_sensitive = True
                sensitive.append(api)
                
                # 生成测试向量
                vectors = self._generate_test_vectors(api)
                api.test_vectors = vectors
                test_vectors.extend(vectors)
            
            # 检测可测试操作
            if self._is_testable_operation(path):
                testable.append(api)
            
            apis.append(api)
        
        return {
            'total': len(apis),
            'apis': [a.url for a in apis],
            'sensitive': [{'url': a.url, 'method': a.method, 'semantic': a.semantic_type} for a in sensitive],
            'testable': [{'url': a.url, 'method': a.method, 'semantic': a.semantic_type} for a in testable],
            'test_vectors': test_vectors,
            'hooked_apis': apis,
        }
    
    def _parse_params(self, data: Any, params: Any) -> Dict:
        """解析参数"""
        result = {}
        
        if isinstance(data, dict):
            result.update(data)
        elif isinstance(data, str):
            try:
                result = json.loads(data) if data else {}
            except:
                # URL encoded
                for pair in data.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        result[k] = v
        
        if isinstance(params, dict):
            result.update(params)
        
        return result
    
    def _infer_semantic_type(self, path: str, method: str) -> str:
        """推断语义类型"""
        path_lower = path.lower()
        
        if 'login' in path_lower or 'signin' in path_lower:
            return 'login'
        if 'reset' in path_lower and 'pass' in path_lower:
            return 'reset_password'
        if 'forgot' in path_lower or 'recovery' in path_lower:
            return 'forgot_password'
        if 'logout' in path_lower:
            return 'logout'
        if 'profile' in path_lower:
            return 'user_profile'
        if 'avatar' in path_lower:
            return 'avatar_upload'
        if 'user' in path_lower and ('add' in path_lower or 'create' in path_lower):
            return 'create_user'
        if 'user' in path_lower and ('delete' in path_lower or 'remove' in path_lower):
            return 'delete_user'
        if 'user' in path_lower and ('modify' in path_lower or 'update' in path_lower or 'edit' in path_lower):
            return 'modify_user'
        if 'password' in path_lower or 'passwd' in path_lower:
            return 'password_operation'
        if 'admin' in path_lower:
            return 'admin_operation'
        
        return 'general'
    
    def _is_sensitive_operation(self, path: str, method: str) -> bool:
        """判断是否为敏感操作"""
        path_lower = path.lower()
        
        sensitive_keywords = [
            'password', 'passwd', 'pwd',
            'login', 'logout', 'auth',
            'reset', 'forgot', 'recovery',
            'credit', 'card', 'payment', 'money',
            'private', 'secret', 'key',
        ]
        
        for keyword in sensitive_keywords:
            if keyword in path_lower:
                return True
        
        # 危险方法
        if method in ['POST', 'PUT', 'DELETE'] and any(k in path_lower for k in ['user', 'admin', 'password', 'auth']):
            return True
        
        return False
    
    def _is_testable_operation(self, path: str) -> bool:
        """判断是否可测试"""
        path_lower = path.lower()
        
        testable_keywords = [
            'reset', 'forgot', 'recovery',
            'password', 'passwd',
            'delete', 'remove',
            'admin', 'manage',
            'user', 'profile',
            'modify', 'update', 'edit',
            'upload', 'download',
        ]
        
        return any(keyword in path_lower for keyword in testable_keywords)
    
    def _generate_test_vectors(self, api: HookedAPI) -> List[Dict]:
        """生成测试向量"""
        vectors = []
        path = api.url.lower()
        method = api.method.upper()
        params = api.params
        
        # 1. 未授权访问测试
        if method in ['GET', 'POST', 'PUT', 'DELETE']:
            vectors.append({
                'type': 'unauthorized_access',
                'url': api.url,
                'method': method,
                'description': f'测试未授权访问 {path}',
                'expected': '应该返回 401/403 或需要认证',
            })
        
        # 2. 参数篡改测试
        if params:
            for param_name in list(params.keys())[:3]:
                vectors.append({
                    'type': 'parameter_tampering',
                    'url': api.url,
                    'method': method,
                    'param': param_name,
                    'description': f'篡改参数 {param_name}',
                    'test_value': 'admin\' OR \'1\'=\'1',
                })
        
        # 3. 密码重置相关测试
        if 'reset' in path and 'password' in path:
            vectors.append({
                'type': 'password_reset_bypass',
                'url': api.url,
                'method': method,
                'description': '测试任意密码重置',
                'test_vectors': [
                    {'user_id': '1', 'new_password': 'hacked123'},
                    {'username': 'admin', 'token': 'fake_token'},
                    {'email': 'admin@test.com'},
                ]
            })
        
        # 4. 用户操作测试
        if 'user' in path or 'admin' in path:
            if method == 'DELETE':
                vectors.append({
                    'type': 'idor',
                    'url': api.url,
                    'method': method,
                    'description': '测试 IDOR - 任意用户删除',
                    'test_ids': [1, 2, 3, 'admin'],
                })
            elif method == 'PUT' or 'post' in method.lower():
                vectors.append({
                    'type': 'privilege_escalation',
                    'url': api.url,
                    'method': method,
                    'description': '测试权限提升',
                    'test_role': 'admin',
                })
        
        return vectors


def run_api_hook(target: str) -> Dict:
    """运行 API Hook"""
    print("=" * 60)
    print("API Hook - 参数提取与安全测试")
    print("=" * 60)
    
    interceptor = APIInterceptor(target)
    results = interceptor.hook_all_apis()
    
    print("\n" + "=" * 60)
    print("Hook 结果")
    print("=" * 60)
    print(f"总 API 调用: {results['total']}")
    print(f"敏感操作: {len(results['sensitive'])}")
    print(f"可测试操作: {len(results['testable'])}")
    print(f"测试向量: {len(results['test_vectors'])}")
    
    if results['sensitive']:
        print("\n敏感操作:")
        for s in results['sensitive'][:10]:
            print(f"  [{s['method']}] {s['url']} ({s['semantic']})")
    
    if results['test_vectors']:
        print("\n测试向量示例:")
        for tv in results['test_vectors'][:5]:
            print(f"  [{tv['type']}] {tv['method']} {tv['url']}")
            print(f"    {tv['description']}")
    
    return results


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://58.215.18.57:91"
    run_api_hook(target)
