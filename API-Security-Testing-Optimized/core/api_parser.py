#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版 API 端点解析器

功能:
1. 使用 AST 和正则提取 API 端点和参数
2. 识别参数类型 (path, query, body)
3. 识别参数约束 (required, optional, enum)
4. 父路径探测
5. API 语义分析

使用方式:
    from core.api_parser import APIEndpointParser
    
    parser = APIEndpointParser(target, session)
    result = parser.parse_js_files(js_files)
    result = parser.probe_parent_paths()
"""

import re
import sys
import json
import requests
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs
from enum import Enum

sys.path.insert(0, '/workspace/skill-play/API-Security-Testing-Optimized')


class ParamType(Enum):
    """参数类型"""
    PATH = "path"           # /users/{id}
    QUERY = "query"         # /users?id=1
    BODY = "body"           # POST data
    HEADER = "header"       # Authorization


class ParamLocation(Enum):
    """参数位置"""
    URL = "url"
    FORM = "form"
    JSON = "json"
    HEADER = "header"


@dataclass
class APIParam:
    """API 参数"""
    name: str
    param_type: ParamType
    location: ParamLocation
    required: bool = True
    data_type: str = "string"  # string, number, boolean, object, array
    enum_values: List[Any] = field(default_factory=list)
    description: str = ""
    example: Any = None


@dataclass
class ParsedEndpoint:
    """解析后的 API 端点"""
    path: str
    method: str = "GET"
    params: List[APIParam] = field(default_factory=list)
    source: str = ""
    raw_url: str = ""
    auth_required: bool = False
    description: str = ""
    semantic_type: str = ""  # user_query, file_upload, auth, etc.
    
    def get_path_params(self) -> List[APIParam]:
        return [p for p in self.params if p.param_type == ParamType.PATH]
    
    def get_query_params(self) -> List[APIParam]:
        return [p for p in self.params if p.param_type == ParamType.QUERY]
    
    def has_params(self) -> bool:
        return len(self.params) > 0
    
    def to_dict(self) -> Dict:
        return {
            'path': self.path,
            'method': self.method,
            'params': [{'name': p.name, 'type': p.param_type.value, 'required': p.required} for p in self.params],
            'source': self.source,
            'semantic_type': self.semantic_type,
        }


class APIEndpointParser:
    """API 端点解析器"""
    
    def __init__(self, target: str, session: requests.Session = None):
        self.target = target
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.parsed_endpoints: List[ParsedEndpoint] = []
        self.parent_paths: Set[str] = set()
        self.js_files: List[str] = []
    
    def discover_js_files(self) -> List[str]:
        """发现 JS 文件"""
        try:
            resp = self.session.get(self.target, timeout=10)
            patterns = [
                r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, resp.text)
                for match in matches:
                    if match.startswith('/'):
                        url = self.target.rstrip('/') + match
                    elif match.startswith('http'):
                        url = match
                    else:
                        continue
                    
                    if self.target.replace('http://', '').replace('https://', '').split('/')[0] in url:
                        if url not in self.js_files:
                            self.js_files.append(url)
            
            return self.js_files
            
        except Exception as e:
            print(f"  [WARN] JS 文件发现失败: {e}")
            return []
    
    def parse_js_files(self, js_files: List[str] = None) -> List[ParsedEndpoint]:
        """解析 JS 文件中的 API 端点"""
        if js_files is None:
            js_files = self.discover_js_files()
        
        print(f"  [API Parser] 解析 {len(js_files)} 个 JS 文件...")
        
        for js_url in js_files:
            try:
                resp = self.session.get(js_url, timeout=10)
                content = resp.text
                
                # 使用多种方法提取
                endpoints = self._extract_axios_endpoints(content, js_url)
                endpoints.extend(self._extract_fetch_endpoints(content, js_url))
                endpoints.extend(self._extract_path_patterns(content, js_url))
                endpoints.extend(self._extract_api_definition(content, js_url))
                
                self.parsed_endpoints.extend(endpoints)
                
            except Exception as e:
                print(f"  [WARN] 解析 {js_url}: {e}")
        
        # 去重
        self._deduplicate()
        
        # 提取父路径
        self._extract_parent_paths()
        
        print(f"  [API Parser] 发现 {len(self.parsed_endpoints)} 个端点")
        print(f"  [API Parser] 发现 {len(self.parent_paths)} 个父路径")
        
        return self.parsed_endpoints
    
    def _extract_axios_endpoints(self, content: str, source: str) -> List[ParsedEndpoint]:
        """提取 axios 调用的端点"""
        endpoints = []
        
        # axios.get('/api/users')
        patterns = [
            (r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'axios'),
            (r'this\.\$axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'vue_axios'),
            (r'axios\.(get|post|put|delete|patch)\s*\(\s*`([^`]+)`', 'axios_template'),
        ]
        
        for pattern, ptype in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                method = match[0].upper() if isinstance(match[0], str) and match[0].lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'] else 'GET'
                url = match[1] if isinstance(match, tuple) else match
                
                # 验证是有效的 HTTP 方法
                if method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    continue
                
                endpoint = ParsedEndpoint(
                    path=url,
                    method=method,
                    params=params,
                    source=f'axios_{ptype}',
                    raw_url=url,
                    semantic_type=self._infer_semantic_type(url)
                )
                endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_fetch_endpoints(self, content: str, source: str) -> List[ParsedEndpoint]:
        """提取 fetch 调用的端点"""
        endpoints = []
        
        # fetch('/api/users')
        pattern = r'fetch\s*\(\s*["\']([^"\']+)["\']'
        matches = re.findall(pattern, content, re.IGNORECASE)
        
        for url in matches:
            params = self._extract_params_from_url(url)
            
            endpoint = ParsedEndpoint(
                path=url,
                method='GET',
                params=params,
                source='fetch',
                raw_url=url,
                semantic_type=self._infer_semantic_type(url)
            )
            endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_path_patterns(self, content: str, source: str) -> List[ParsedEndpoint]:
        """提取路径模式 (使用更精确的正则)"""
        endpoints = []
        
        # API 路径模式
        path_patterns = [
            # /api/users/{id}
            (r'["\'](/api/[a-zA-Z0-9_/{}?-]+)["\']', 'GET', 'api_path'),
            # /users/{id}
            (r'["\'](/users/[a-zA-Z0-9_/{}?-]+)["\']', 'GET', 'users_path'),
            # /v1/admin/*
            (r'["\'](/v\d+/[a-zA-Z0-9_/{}?-]+)["\']', 'GET', 'versioned_api'),
            # RESTful 模式
            (r'["\'](/[a-z]+/[a-z]+/[a-zA-Z0-9_/{}?-]+)["\']', 'GET', 'restful'),
        ]
        
        for pattern, default_method, ptype in path_patterns:
            matches = re.findall(pattern, content)
            for url in matches:
                if self._is_valid_api_path(url):
                    params = self._extract_params_from_url(url)
                    
                    endpoint = ParsedEndpoint(
                        path=url,
                        method=default_method,
                        params=params,
                        source=ptype,
                        raw_url=url,
                        semantic_type=self._infer_semantic_type(url)
                    )
                    endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_api_definition(self, content: str, source: str) -> List[ParsedEndpoint]:
        """从 API 定义中提取 (如 swagger 风格)"""
        endpoints = []
        
        # 查找 API 配置对象 - 只匹配有效的 HTTP 方法
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        
        patterns = [
            # { method: 'get', url: '/api/users' }
            r'["\']?(method|http_method)["\']?\s*:\s*["\'](\w+)["\']',
            # fetch/axios config
            r'["\']?(method)["\']?\s*:\s*["\'](\w+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) >= 2:
                    method_str = match[1].upper()
                    if method_str in valid_methods:
                        # 查找附近的 URL
                        url_match = re.search(r'["\']([/a-zA-Z0-9_{}?-]+)["\']', content[content.find(match[0]):content.find(match[0])+200])
                        if url_match:
                            url = url_match.group(0).strip('"\'')
                            if self._is_valid_api_path(url):
                                params = self._extract_params_from_url(url)
                                
                                endpoint = ParsedEndpoint(
                                    path=url,
                                    method=method_str,
                                    params=params,
                                    source='api_definition',
                                    raw_url=url,
                                    semantic_type=self._infer_semantic_type(url)
                                )
                                endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_params_from_url(self, url: str) -> List[APIParam]:
        """从 URL 中提取参数"""
        params = []
        
        # 路径参数 {id}, :id, /{id}
        path_patterns = [
            r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}',  # {id}
            r':([a-zA-Z_][a-zA-Z0-9_]*)',      # :id
        ]
        
        for pattern in path_patterns:
            matches = re.findall(pattern, url)
            for param_name in matches:
                # 推断类型
                data_type = self._infer_param_type(param_name)
                
                params.append(APIParam(
                    name=param_name,
                    param_type=ParamType.PATH,
                    location=ParamLocation.URL,
                    required=True,
                    data_type=data_type
                ))
        
        # 查询参数 ?key=value
        if '?' in url:
            query_str = url.split('?')[1] if '?' in url else ''
            query_params = query_str.split('&')
            for qp in query_params:
                if '=' in qp:
                    param_name = qp.split('=')[0]
                    if param_name and param_name not in [p.name for p in params]:
                        params.append(APIParam(
                            name=param_name,
                            param_type=ParamType.QUERY,
                            location=ParamLocation.URL,
                            required=False,
                            data_type='string'
                        ))
        
        return params
    
    def _is_valid_api_path(self, path: str) -> bool:
        """验证是否是有效的 API 路径"""
        if not path or len(path) < 2:
            return False
        
        if not path.startswith('/'):
            return False
        
        # 排除明显不是 API 的路径
        skip_patterns = [
            r'\.(css|js|jpg|jpeg|png|gif|ico|svg|woff|ttf)$',
            r'^/static/',
            r'^/public/',
            r'^/assets/',
            r'^/images/',
            r'^/styles/',
        ]
        
        for pattern in skip_patterns:
            if re.search(pattern, path, re.I):
                return False
        
        # 必须是有效的路径模式
        if re.match(r'^/[a-zA-Z]', path):
            return True
        
        return False
    
    def _infer_param_type(self, param_name: str) -> str:
        """推断参数类型"""
        name_lower = param_name.lower()
        
        type_hints = {
            'id': 'number',
            'user_id': 'number',
            'order_id': 'number',
            'page': 'number',
            'limit': 'number',
            'size': 'number',
            'count': 'number',
            'page_size': 'number',
            'is_': 'boolean',
            'has_': 'boolean',
            'enable': 'boolean',
            'active': 'boolean',
            'enabled': 'boolean',
            'list': 'array',
            'ids': 'array',
            'data': 'object',
            'info': 'object',
            'params': 'object',
            'options': 'object',
        }
        
        for hint, dtype in type_hints.items():
            if hint in name_lower:
                return dtype
        
        return 'string'
    
    def _infer_semantic_type(self, path: str) -> str:
        """推断 API 的语义类型"""
        path_lower = path.lower()
        
        semantic_mappings = {
            'auth': ['/auth', '/login', '/logout', '/token', '/signin', '/signup'],
            'user': ['/user', '/profile', '/account', '/avatar'],
            'admin': ['/admin', '/manage', '/system', '/config'],
            'file': ['/file', '/upload', '/download', '/attachment', '/image', '/avatar'],
            'order': ['/order', '/cart', '/checkout', '/payment'],
            'product': ['/product', '/goods', '/item', '/sku'],
            'data': ['/data', '/statistics', '/report', '/analytics'],
            'api': ['/api', '/v1', '/v2', '/rest'],
            'search': ['/search', '/query', '/find'],
            'list': ['/list', '/items', '/records'],
            'detail': ['/detail', '/info', '/view'],
            'create': ['/create', '/add', '/new'],
            'update': ['/update', '/edit', '/modify', '/put'],
            'delete': ['/delete', '/remove', '/del'],
        }
        
        for semantic_type, keywords in semantic_mappings.items():
            for keyword in keywords:
                if keyword in path_lower:
                    return semantic_type
        
        return 'unknown'
    
    def _extract_parent_paths(self):
        """提取父路径"""
        for ep in self.parsed_endpoints:
            path = ep.path
            
            # 分解路径，提取所有父路径
            parts = path.strip('/').split('/')
            
            for i in range(1, len(parts)):
                parent = '/' + '/'.join(parts[:i])
                if parent != path:  # 不包括自身
                    self.parent_paths.add(parent)
            
            # 也包括根路径
            if len(parts) > 0:
                self.parent_paths.add('/' + parts[0])
        
        # 过滤
        valid_parents = set()
        for parent in self.parent_paths:
            if self._is_valid_api_path(parent):
                valid_parents.add(parent)
        
        self.parent_paths = valid_parents
    
    def _deduplicate(self):
        """去重"""
        seen = set()
        unique = []
        
        for ep in self.parsed_endpoints:
            key = f"{ep.method}:{ep.path}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        
        self.parsed_endpoints = unique
    
    def probe_parent_paths(self) -> Dict[str, Any]:
        """探测父路径，返回可访问的路径"""
        print(f"  [API Parser] 探测父路径 ({len(self.parent_paths)} 个)...")
        
        accessible_paths = {}
        
        for parent in self.parent_paths:
            url = self.target.rstrip('/') + parent
            try:
                r = self.session.get(url, timeout=5, allow_redirects=False)
                
                result = {
                    'path': parent,
                    'status': r.status_code,
                    'content_type': r.headers.get('Content-Type', ''),
                    'is_api': 'json' in r.headers.get('Content-Type', '').lower() or '{' in r.text[:100],
                    'content_length': len(r.text),
                }
                
                accessible_paths[parent] = result
                
                if result['is_api']:
                    print(f"    [API] {parent}: {r.status_code}")
                
            except Exception as e:
                pass
        
        return accessible_paths
    
    def get_endpoints_summary(self) -> str:
        """获取端点摘要"""
        summary = []
        summary.append(f"端点总数: {len(self.parsed_endpoints)}")
        
        # 按方法统计
        methods = {}
        for ep in self.parsed_endpoints:
            m = ep.method
            methods[m] = methods.get(m, 0) + 1
        
        summary.append("按方法:")
        for m, count in sorted(methods.items()):
            summary.append(f"  {m}: {count}")
        
        # 按语义类型统计
        semantic = {}
        for ep in self.parsed_endpoints:
            t = ep.semantic_type or 'unknown'
            semantic[t] = semantic.get(t, 0) + 1
        
        summary.append("按语义类型:")
        for t, count in sorted(semantic.items(), key=lambda x: -x[1]):
            summary.append(f"  {t}: {count}")
        
        # 带参数的端点
        with_params = sum(1 for ep in self.parsed_endpoints if ep.has_params())
        summary.append(f"带参数端点: {with_params}")
        
        return "\n".join(summary)


class APIFuzzer:
    """API Fuzzer - 对发现的端点进行模糊测试"""
    
    def __init__(self, target: str, session: requests.Session = None):
        self.target = target
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.fuzz_results = []
    
    def fuzz_endpoints(self, endpoints: List[ParsedEndpoint], parent_probe_result: Dict = None) -> List[Dict]:
        """对端点进行 fuzzing"""
        print(f"\n  [Fuzzer] Fuzzing {len(endpoints)} 个端点...")
        
        fuzz_results = []
        
        # 常见 fuzzing payload
        fuzz_payloads = {
            'sqli': [
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
            ],
            'xss': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//etc/passwd",
            ],
            'cmd_injection': [
                "; ls",
                "| cat /etc/passwd",
                "`whoami`",
                "$(whoami)",
            ],
            'ssti': [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
            ],
        }
        
        for ep in endpoints:
            url = self.target.rstrip('/') + ep.path
            
            # 测试 SQL 注入
            for payload in fuzz_payloads['sqli'][:2]:
                result = self._test_sqli(url, ep, payload)
                if result:
                    fuzz_results.append(result)
            
            # 测试 XSS
            for payload in fuzz_payloads['xss'][:1]:
                result = self._test_xss(url, ep, payload)
                if result:
                    fuzz_results.append(result)
            
            # 测试路径遍历
            for payload in fuzz_payloads['path_traversal'][:1]:
                result = self._test_path_traversal(url, ep, payload)
                if result:
                    fuzz_results.append(result)
        
        # 对父路径进行 fuzzing
        if parent_probe_result:
            for path, info in parent_probe_result.items():
                if info.get('is_api'):
                    url = self.target.rstrip('/') + path
                    
                    # 尝试添加参数
                    test_urls = [
                        url + '?id=1',
                        url + '?id=1 OR 1=1',
                        url + '?q=<script>alert(1)</script>',
                    ]
                    
                    for test_url in test_urls:
                        result = self._test_url(test_url, path)
                        if result:
                            fuzz_results.append(result)
        
        self.fuzz_results = fuzz_results
        print(f"  [Fuzzer] 发现 {len(fuzz_results)} 个问题")
        
        return fuzz_results
    
    def _test_sqli(self, url: str, ep: ParsedEndpoint, payload: str) -> Optional[Dict]:
        """测试 SQL 注入"""
        try:
            # 如果有 path 参数，替换它
            test_url = url
            for param in ep.get_path_params():
                test_url = re.sub(r'\{' + param.name + r'\}', payload, test_url)
                test_url = re.sub(r':' + param.name, payload, test_url)
            
            # 如果 URL 没有参数，添加到末尾
            if '?' not in test_url:
                test_url = test_url + '?id=' + payload
            
            r = self.session.get(test_url, timeout=5)
            
            sqli_indicators = [
                'sql', 'syntax', 'mysql', 'oracle', 'error in your sql',
                'postgresql', 'sqlite', 'mariadb', 'sqlstate', 'odbc'
            ]
            
            resp_lower = r.text.lower()
            for indicator in sqli_indicators:
                if indicator in resp_lower:
                    return {
                        'type': 'SQL Injection',
                        'severity': 'CRITICAL',
                        'url': test_url,
                        'payload': payload,
                        'endpoint': ep.path,
                        'evidence': f'SQL error indicator: {indicator}',
                    }
        
        except Exception as e:
            pass
        
        return None
    
    def _test_xss(self, url: str, ep: ParsedEndpoint, payload: str) -> Optional[Dict]:
        """测试 XSS"""
        try:
            test_url = url
            for param in ep.get_path_params():
                test_url = re.sub(r'\{' + param.name + r'\}', payload, test_url)
            
            if '?' not in test_url:
                test_url = test_url + '?q=' + payload
            else:
                test_url = test_url + '&q=' + payload
            
            r = self.session.get(test_url, timeout=5)
            
            if payload in r.text:
                return {
                    'type': 'XSS (Reflected)',
                    'severity': 'HIGH',
                    'url': test_url,
                    'payload': payload,
                    'endpoint': ep.path,
                    'evidence': 'Payload reflected in response',
                }
        
        except Exception as e:
            pass
        
        return None
    
    def _test_path_traversal(self, url: str, ep: ParsedEndpoint, payload: str) -> Optional[Dict]:
        """测试路径遍历"""
        try:
            test_url = url.rstrip('/') + '/' + payload
            
            r = self.session.get(test_url, timeout=5)
            
            if 'root:' in r.text or '[extensions]' in r.text or 'boot.ini' in r.text:
                return {
                    'type': 'Path Traversal',
                    'severity': 'HIGH',
                    'url': test_url,
                    'payload': payload,
                    'endpoint': ep.path,
                    'evidence': 'Sensitive file content exposed',
                }
        
        except Exception as e:
            pass
        
        return None
    
    def _test_url(self, url: str, base_path: str) -> Optional[Dict]:
        """测试 URL"""
        try:
            r = self.session.get(url, timeout=5)
            
            # 检查是否反射 payload
            sqli_payloads = ["' OR '1'='1", "1 OR 1=1"]
            xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
            
            for payload in sqli_payloads:
                if payload in r.text and 'sql' in r.text.lower():
                    return {
                        'type': 'SQL Injection',
                        'severity': 'CRITICAL',
                        'url': url,
                        'payload': payload,
                        'endpoint': base_path,
                        'evidence': 'Potential SQL injection',
                    }
            
            for payload in xss_payloads:
                if payload in r.text:
                    return {
                        'type': 'XSS (Reflected)',
                        'severity': 'HIGH',
                        'url': url,
                        'payload': payload,
                        'endpoint': base_path,
                        'evidence': 'Payload reflected',
                    }
        
        except Exception as e:
            pass
        
        return None
