#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SKILL.md 的完整可执行实现

模块联动流程：
1. TestContext - 共享测试上下文（session、endpoints、vulnerabilities）
2. PrerequisiteChecker - 前置检查
3. AssetDiscovery - 端点发现（静态+动态+Hook）
4. VulnerabilityTester - 漏洞测试
5. APIFuzzer - 模糊测试
6. CloudStorageTester - 云存储测试
7. ReportGenerator - 报告生成

使用方式:
    python3 -m core.runner http://target.com
"""

import sys
import re
import time
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field

sys.path.insert(0, '/workspace/skill-play/API-Security-Testing-Optimized')

logger = logging.getLogger(__name__)


@dataclass
class TestContext:
    """
    测试上下文 - 各模块共享数据
    """
    target: str
    session: Any = None
    
    # 共享数据
    endpoints: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    cloud_findings: List[Dict] = field(default_factory=list)
    parent_paths: Dict = field(default_factory=dict)
    tech_stack: Dict = field(default_factory=dict)
    
    # Hook 到的 API
    hooked_apis: List[Dict] = field(default_factory=list)
    sensitive_apis: List[Dict] = field(default_factory=list)
    test_vectors: List[Dict] = field(default_factory=list)
    
    # 状态
    playwright_available: bool = False
    backend_reachable: bool = True
    nginx_fallback: bool = False
    
    def add_endpoints(self, endpoints: List[Dict]):
        """添加端点（去重）"""
        existing = set((e.get('method', 'GET'), e.get('path', '')) for e in self.endpoints)
        for ep in endpoints:
            key = (ep.get('method', 'GET'), ep.get('path', ''))
            if key not in existing:
                self.endpoints.append(ep)
                existing.add(key)
    
    def add_vulnerability(self, vuln: Dict):
        """添加漏洞（去重）"""
        key = (vuln.get('type', ''), vuln.get('endpoint', ''))
        existing = set((v.get('type', ''), v.get('endpoint', '')) for v in self.vulnerabilities)
        if key not in existing:
            self.vulnerabilities.append(vuln)
    
    def get_all_endpoints(self) -> List[Dict]:
        """获取所有端点（包括 Hook 到的）"""
        all_eps = list(self.endpoints)
        for hook in self.hooked_apis:
            path = hook.get('path', hook.get('url', ''))
            method = hook.get('method', 'GET')
            if not any(e.get('path') == path and e.get('method') == method for e in all_eps):
                all_eps.append(hook)
        return all_eps


class PrerequisiteChecker:
    """阶段 0: 前置检查"""
    
    @staticmethod
    def check(ctx: TestContext) -> bool:
        """检查所有依赖，设置上下文"""
        from core.prerequisite import prerequisite_check
        
        print("[0] 前置检查")
        print("-" * 70)
        
        # 使用新的前置检查模块 (支持平替检测和自动安装)
        playwright_available, browser_type, can_proceed = prerequisite_check()
        
        ctx.playwright_available = playwright_available
        
        # requests 检查
        try:
            import requests
            ctx.session = requests.Session()
            ctx.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            print("  [OK] requests")
        except ImportError:
            print("  [FAIL] requests")
            return False
        
        if not can_proceed:
            print("\n[FATAL] 前置检查失败 - 缺少无头浏览器支持")
            return False
        
        print()
        return ctx.playwright_available and ctx.session is not None


class AssetDiscovery:
    """阶段 1: 资产发现
    
    使用 TestContext 共享数据
    """
    
    def __init__(self, ctx: TestContext):
        self.ctx = ctx
        self.target = ctx.target
        self.session = ctx.session
        self.js_files = []
    
    def run(self):
        """执行资产发现（联动各模块）"""
        print("[1] 资产发现")
        print("-" * 70)
        
        # 1.1 目标探测
        self._probe_target()
        
        # 1.2 静态分析 (api_parser)
        self._parse_with_api_parser()
        
        # 1.3 动态分析 (dynamic_api_analyzer)
        self._analyze_dynamic()
        
        # 1.4 API Hook (api_interceptor) - 获取真实参数
        self._hook_apis()
        
        # 1.5 父路径探测
        self._probe_parent_paths()
        
        # 更新上下文
        self.ctx.backend_reachable = len([p for p in self.ctx.parent_paths.values() if p.get('is_api')]) > 0
        self.ctx.nginx_fallback = not self.ctx.backend_reachable
        
        print(f"\n  发现端点: {len(self.ctx.endpoints)}")
        print(f"  Hook API: {len(self.ctx.hooked_apis)}")
        print(f"  敏感 API: {len(self.ctx.sensitive_apis)}")
        print(f"  父路径: {len(self.ctx.parent_paths)}")
        print(f"  技术栈: {self.ctx.tech_stack}")
        print()
        
        return self.ctx
    
    def _probe_target(self):
        """基础探测"""
        try:
            r = self.session.get(self.target, timeout=10)
            
            server = r.headers.get('Server', 'Unknown')
            print(f"  Server: {server}")
            
            html = r.text.lower()
            if 'vue' in html:
                self.ctx.tech_stack['frontend'] = 'Vue.js'
            if 'react' in html:
                self.ctx.tech_stack['frontend'] = 'React'
            if 'jquery' in html:
                self.ctx.tech_stack['jquery'] = True
            if 'element' in html:
                self.ctx.tech_stack['ui'] = 'ElementUI'
            if 'angular' in html:
                self.ctx.tech_stack['frontend'] = 'Angular'
            
            cors = r.headers.get('Access-Control-Allow-Origin', '未设置')
            print(f"  CORS: {cors}")
            
        except Exception as e:
            print(f"  [WARN] 目标探测失败: {e}")
    
    def _infer_semantic_type(self, path: str) -> str:
        """推断路径的语义类型"""
        path_lower = path.lower()
        
        mappings = {
            'auth': ['/auth', '/login', '/logout', '/token', '/signin'],
            'user': ['/user', '/profile', '/account', '/avatar'],
            'admin': ['/admin', '/manage', '/system', '/config'],
            'file': ['/file', '/upload', '/download', '/attachment', '/image'],
            'order': ['/order', '/cart', '/checkout'],
            'product': ['/product', '/goods', '/sku'],
            'data': ['/data', '/statistics', '/report', '/analytics'],
            'api': ['/api', '/v1', '/v2', '/rest'],
            'search': ['/search', '/query', '/find'],
            'list': ['/list', '/items', '/records'],
            'detail': ['/detail', '/info', '/view'],
            'create': ['/create', '/add', '/new'],
            'update': ['/update', '/edit', '/modify'],
            'delete': ['/delete', '/remove'],
        }
        
        for semantic, keywords in mappings.items():
            for keyword in keywords:
                if keyword in path_lower:
                    return semantic
        
        return 'unknown'
    
    def _parse_with_api_parser(self):
        """静态分析 (api_parser)"""
        try:
            from core.api_parser import APIEndpointParser
            
            parser = APIEndpointParser(self.target, self.session)
            self.js_files = parser.discover_js_files()
            print(f"  发现 JS 文件: {len(self.js_files)}")
            
            parsed_endpoints = parser.parse_js_files(self.js_files)
            
            for ep in parsed_endpoints:
                self.ctx.add_endpoints([{
                    'path': ep.path,
                    'method': ep.method,
                    'params': [{'name': p.name, 'type': p.param_type.value, 'required': p.required} for p in ep.params],
                    'source': ep.source,
                    'semantic_type': ep.semantic_type,
                    'has_params': ep.has_params(),
                }])
            
            print(f"  静态解析: {len(parsed_endpoints)} 端点")
            
        except Exception as e:
            print(f"  [WARN] API Parser 失败: {e}")
            
        except Exception as e:
            print(f"  [WARN] API Parser 失败: {e}")
    
    def _analyze_dynamic(self):
        """动态分析 (dynamic_api_analyzer)"""
        try:
            from core.dynamic_api_analyzer import DynamicAPIAnalyzer
            
            analyzer = DynamicAPIAnalyzer(self.target)
            results = analyzer.analyze_full()
            
            for ep in results.get('endpoints', []):
                path = ep.get('path', '')
                method = ep.get('method', 'GET')
                params_data = ep.get('params', [])
                if isinstance(params_data, list):
                    params_dict = {p: True for p in params_data}
                else:
                    params_dict = params_data
                
                self.ctx.add_endpoints([{
                    'path': path,
                    'method': method,
                    'params': params_dict,
                    'source': f"dynamic_{ep.get('source', 'unknown')}",
                    'semantic_type': self._infer_semantic_type(path),
                }])
            
            print(f"  动态分析: {results.get('unique_endpoints', 0)} 端点")
            
        except Exception as e:
            print(f"  [WARN] Dynamic API Analyzer 失败: {e}")
    
    def _hook_apis(self):
        """API Hook (api_interceptor)"""
        if not self.ctx.playwright_available:
            print("  [SKIP] Playwright 不可用")
            return
        
        try:
            from core.api_interceptor import APIInterceptor
            
            print("  [API Hook] 启动...")
            interceptor = APIInterceptor(self.target)
            hook_results = interceptor.hook_all_apis()
            
            # 保存 Hook 结果到上下文
            self.ctx.hooked_apis = hook_results.get('endpoints', [])
            self.ctx.sensitive_apis = hook_results.get('sensitive', [])
            self.ctx.test_vectors = hook_results.get('test_vectors', [])
            
            # 将 Hook 到的端点添加到上下文的端点列表
            for hooked_ep in hook_results.get('endpoints', []):
                path = hooked_ep.get('path', hooked_ep.get('url', ''))
                if path and '/' in path:
                    self.ctx.add_endpoints([{
                        'path': path,
                        'method': hooked_ep.get('method', 'GET'),
                        'params': hooked_ep.get('params', {}),
                        'source': f"hooked_{hooked_ep.get('source', 'unknown')}",
                        'semantic_type': hooked_ep.get('semantic', 'unknown'),
                    }])
            
            print(f"  API Hook: {len(self.ctx.hooked_apis)} 个 API 调用")
            print(f"  敏感操作: {len(self.ctx.sensitive_apis)} 个")
            print(f"  测试向量: {len(self.ctx.test_vectors)} 个")
            
        except Exception as e:
            print(f"  [WARN] API Hook 失败: {e}")
    
    def _probe_parent_paths(self):
        """父路径探测"""
        try:
            from core.api_parser import APIEndpointParser
            
            parser = APIEndpointParser(self.target, self.session)
            parser.discover_js_files()
            
            # 获取解析后的父路径（set 格式）
            parsed_endpoints = parser.parse_js_files(self.js_files)
            
            # 转换 set 为 dict 格式
            for parent in parser.parent_paths:
                url = self.target.rstrip('/') + parent
                try:
                    r = self.session.get(url, timeout=5, allow_redirects=False)
                    self.ctx.parent_paths[parent] = {
                        'path': parent,
                        'status': r.status_code,
                        'is_api': 'json' in r.headers.get('Content-Type', '').lower() or '{' in r.text[:100],
                    }
                except:
                    pass
            
            print(f"  父路径: {len(self.ctx.parent_paths)} 个")
            
        except Exception as e:
            print(f"  [WARN] 父路径探测失败: {e}")


class VulnerabilityTester:
    """阶段 2: 多维度漏洞分析"""
    
    def __init__(self, ctx: TestContext):
        self.ctx = ctx
        self.target = ctx.target
        self.session = ctx.session
    
    def run(self) -> List:
        """执行漏洞测试"""
        print("[2] 多维度漏洞分析")
        print("-" * 70)
        
        # 使用上下文中所有端点（包括 Hook 到的）
        self.endpoints = self.ctx.get_all_endpoints()
        
        # 2.1 SQL 注入测试
        self._test_sqli()
        
        # 2.2 XSS 测试
        self._test_xss()
        
        # 2.3 路径遍历测试
        self._test_path_traversal()
        
        # 2.4 敏感信息泄露
        self._test_sensitive_exposure()
        
        # 2.5 认证绕过测试
        self._test_auth_bypass()
        
        # 2.6 GraphQL 测试 (如果发现 GraphQL 端点)
        self._test_graphql()
        
        # 2.7 暴力破解测试 (如果发现登录端点)
        self._test_brute_force()
        
        # 2.8 IDOR 测试
        self._test_idor()
        
        print(f"\n  发现漏洞: {len(self.ctx.vulnerabilities)}")
        print()
        
        return self.ctx.vulnerabilities
    
    def _test_sqli(self):
        """SQL 注入测试"""
        print("  [SQL注入] 测试...")
        
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "admin'--",
        ]
        
        for ep in self.endpoints[:20]:
            if ep.get('method') != 'GET':
                continue
            
            url = ep.get('url', self.target + ep.get('path', ''))
            if '?' not in url:
                url = url + '?id=1'
            
            try:
                for payload in sqli_payloads[:2]:
                    test_url = url.replace('id=1', f'id={payload}')
                    r = self.session.get(test_url, timeout=5)
                    
                    # 跳过 HTML 响应（通常是 nginx fallback）
                    content_type = r.headers.get('Content-Type', '')
                    if 'text/html' in content_type or r.text.strip().startswith('<!DOCTYPE'):
                        continue
                    
                    # 检查是否是 JSON 响应
                    if 'application/json' not in content_type and '{' not in r.text[:100]:
                        continue
                    
                    # SQL 注入特征检测（排除假阳性）
                    text_lower = r.text.lower()
                    # 真正的 SQL 错误特征
                    sql_patterns = ['sql syntax', 'sql error', 'mysql', 'oracle', 'sqlite', 
                                   'sqlstate', 'postgresql', 'sqlserver', 'column', 'table',
                                   'mysqli_', 'pdo_', 'odbc_']
                    if any(p in text_lower for p in sql_patterns):
                        self.ctx.add_vulnerability({
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'endpoint': url,
                            'payload': payload,
                            'evidence': 'SQL error detected'
                        })
                        print(f"    [!] {ep['path']}: SQL注入")
                        break
            except:
                pass
    
    def _test_xss(self):
        """XSS 测试"""
        print("  [XSS] 测试...")
        
        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
        ]
        
        for ep in self.endpoints[:20]:
            if ep.get('method') != 'GET':
                continue
            
            url = ep.get('url', self.target + ep.get('path', ''))
            
            try:
                for payload in xss_payloads[:1]:
                    if '?' in url:
                        test_url = url + '&q=' + payload
                    else:
                        test_url = url + '?q=' + payload
                    
                    r = self.session.get(test_url, timeout=5)
                    
                    if payload in r.text:
                        self.ctx.add_vulnerability({
                            'type': 'XSS (Reflected)',
                            'severity': 'HIGH',
                            'endpoint': url,
                            'payload': payload,
                            'evidence': 'Payload reflected'
                        })
                        print(f"    [!] {ep['path']}: XSS")
                        break
            except:
                pass
    
    def _test_path_traversal(self):
        """路径遍历测试"""
        print("  [路径遍历] 测试...")
        
        pt_payloads = ['../../etc/passwd', '..\\..\\windows\\win.ini', '%2e%2e%2f%2e%2e%2fetc%2fpasswd']
        
        for ep in self.endpoints[:10]:
            url = ep.get('url', self.target + ep.get('path', ''))
            
            try:
                for payload in pt_payloads[:1]:
                    test_url = url + '/' + payload if url.endswith('/') else url + '/' + payload
                    r = self.session.get(test_url, timeout=5)
                    
                    if 'root:' in r.text or '[extensions]' in r.text:
                        self.ctx.add_vulnerability({
                            'type': 'Path Traversal',
                            'severity': 'HIGH',
                            'endpoint': url,
                            'payload': payload,
                            'evidence': 'Sensitive file content exposed'
                        })
                        print(f"    [!] {ep['path']}: 路径遍历")
                        break
            except:
                pass
    
    def _test_sensitive_exposure(self):
        """敏感信息泄露测试"""
        print("  [敏感信息] 检测...")
        
        sensitive_patterns = [
            ('password', 'password', 'MEDIUM'),
            ('secret', 'api_key', 'HIGH'),
            ('token', 'token', 'MEDIUM'),
            ('private_key', 'private_key', 'CRITICAL'),
        ]
        
        for ep in self.endpoints[:30]:
            url = ep.get('url', self.target + ep.get('path', ''))
            
            try:
                r = self.session.get(url, timeout=5)
                
                for pattern, name, severity in sensitive_patterns:
                    if pattern in r.text.lower() and 'password' not in r.text.lower()[:500]:
                        # 避免误报，只在实际内容中检测
                        content_sample = r.text[:1000].lower()
                        if content_sample.count(pattern) > 2:
                            self.ctx.add_vulnerability({
                                'type': 'Sensitive Data Exposure',
                                'severity': severity,
                                'endpoint': url,
                                'evidence': f'{name} found in response',
                            })
                            print(f"    [!] {ep['path']}: 敏感信息 ({name})")
                            break
            except:
                pass
    
    def _test_auth_bypass(self):
        """认证绕过测试"""
        print("  [认证绕过] 测试...")
        
        # 测试不需要认证就能访问的敏感端点
        sensitive_paths = ['/admin', '/api/admin', '/api/users', '/api/config']
        
        for path in sensitive_paths:
            url = self.target.rstrip('/') + path
            try:
                r = self.session.get(url, timeout=5)
                
                if r.status_code == 200 and len(r.text) > 100:
                    ct = r.headers.get('Content-Type', '')
                    if 'json' in ct.lower() or '{' in r.text[:100]:
                        self.ctx.add_vulnerability({
                            'type': 'Authentication Bypass',
                            'severity': 'HIGH',
                            'endpoint': path,
                            'evidence': f'No auth required, status: {r.status_code}'
                        })
                        print(f"    [!] {path}: 无需认证")
            except:
                pass
    
    def _test_graphql(self):
        """GraphQL 测试"""
        graphql_paths = ['/graphql', '/api/graphql', '/query']
        
        for path in graphql_paths:
            url = self.target.rstrip('/') + path
            try:
                r = self.session.post(url, json={'query': '{__schema{types{name}}}'}, timeout=5)
                
                if r.status_code == 200 and 'data' in r.text:
                    self.ctx.add_vulnerability({
                        'type': 'GraphQL Introspection Enabled',
                        'severity': 'MEDIUM',
                        'endpoint': path,
                        'evidence': 'GraphQL schema exposed'
                    })
                    print(f"    [!] {path}: GraphQL 开启 introspection")
                    
                    # 检查 mutation
                    r2 = self.session.post(url, json={'query': 'mutation{__typename}'}, timeout=5)
                    if r2.status_code == 200:
                        print(f"    [!] {path}: mutation 可用")
            except:
                pass
    
    def _test_brute_force(self):
        """暴力破解测试"""
        login_paths = ['/login', '/api/login', '/auth/login', '/signin']
        
        for path in login_paths:
            url = self.target.rstrip('/') + path
            try:
                # 测试多次登录
                for i in range(3):
                    r = self.session.post(url, json={'username': f'test{i}', 'password': 'wrong'}, timeout=5)
                
                # 检查是否有 rate limit
                if r.status_code in [200, 400, 401, 403]:
                    # 发送大量请求测试
                    for i in range(10):
                        r = self.session.post(url, json={'username': 'admin', 'password': 'test'}, timeout=5)
                    
                    # 检查响应是否变化
                    if r.status_code != 429:  # 没有 rate limit
                        self.ctx.add_vulnerability({
                            'type': 'Brute Force Risk',
                            'severity': 'MEDIUM',
                            'endpoint': path,
                            'evidence': 'No rate limiting detected'
                        })
                        print(f"    [!] {path}: 无暴力破解防护")
            except:
                pass
    
    def _test_idor(self):
        """IDOR 测试"""
        idor_paths = ['/user/1', '/users/1', '/profile/1', '/api/user/1']
        
        for path in idor_paths:
            url = self.target.rstrip('/') + path
            try:
                r = self.session.get(url, timeout=5)
                
                if r.status_code == 200:
                    ct = r.headers.get('Content-Type', '')
                    if 'json' in ct.lower():
                        self.ctx.add_vulnerability({
                            'type': 'Potential IDOR',
                            'severity': 'MEDIUM',
                            'endpoint': path,
                            'evidence': 'Direct object reference without auth check'
                        })
                        print(f"    [!] {path}: 可能的 IDOR")
                        break
            except:
                pass


class CloudStorageTester:
    """阶段 3: 云存储安全测试"""
    
    def __init__(self, target: str, session):
        self.target = target
        self.session = session
        self.findings = []
    
    def run(self) -> List:
        """执行云存储测试"""
        print("[3] 云存储安全测试")
        print("-" * 70)
        
        # 检查云存储特征
        cloud_patterns = [
            ('oss', 'aliyun'),
            ('cos', 'qcloud'),
            ('s3', 'aws'),
            ('minio', 'minio'),
            ('obs', 'huawei'),
        ]
        
        for keyword, provider in cloud_patterns:
            try:
                r = self.session.get(self.target, timeout=10)
                
                if keyword in r.text.lower():
                    self.findings.append({
                        'type': f'{provider.upper()} Storage',
                        'severity': 'INFO',
                        'endpoint': self.target,
                        'evidence': f'Cloud storage keyword found: {keyword}'
                    })
                    print(f"  [发现] {provider} 云存储特征")
                
                # 检查响应头
                for header in r.headers:
                    if keyword in header.lower():
                        print(f"  [发现] {provider} header: {header}")
            except:
                pass
        
        if not self.findings:
            print("  未发现云存储特征")
        
        print()
        return self.findings


class ReportGenerator:
    """阶段 4: 报告生成"""
    
    @staticmethod
    def generate(results: Dict) -> str:
        """生成 Markdown 报告"""
        
        report = []
        report.append("# API 安全测试报告")
        report.append("")
        report.append(f"**目标**: {results.get('target', 'N/A')}")
        report.append(f"**时间**: {results.get('timestamp', 'N/A')}")
        report.append(f"**耗时**: {results.get('duration', 0):.1f}s")
        report.append("")
        
        # 统计
        report.append("## 发现统计")
        report.append("")
        report.append(f"- API 端点: {len(results.get('endpoints', []))}")
        report.append(f"- 漏洞: {len(results.get('vulnerabilities', []))}")
        report.append(f"- 云存储: {len(results.get('cloud_findings', []))}")
        report.append("")
        
        # 技术栈
        if results.get('tech_stack'):
            report.append("## 技术栈")
            report.append("")
            for key, value in results['tech_stack'].items():
                report.append(f"- {key}: {value}")
            report.append("")
        
        # 父路径探测结果
        if results.get('parent_paths'):
            parent_paths = results['parent_paths']
            html_fallback = sum(1 for p in parent_paths.values() if not p.get('is_api'))
            real_api = sum(1 for p in parent_paths.values() if p.get('is_api'))
            
            report.append("## 父路径分析")
            report.append("")
            report.append(f"- 总父路径: {len(parent_paths)}")
            report.append(f"- HTML fallback: {html_fallback} (nginx fallback 配置)")
            report.append(f"- JSON API: {real_api}")
            report.append("")
            
            # 检测 nginx fallback 问题
            if html_fallback > 0 and real_api == 0:
                report.append("### 安全问题: nginx fallback 配置")
                report.append("")
                report.append("**问题**: 所有 API 路径都返回 HTML 而不是 JSON API")
                report.append("")
                report.append("**可能原因**:")
                report.append("1. 后端 API 服务未运行 (端口 667 不可达)")
                report.append("2. nginx 未正确配置 API 路径代理")
                report.append("3. API 服务部署在不同的服务器/端口")
                report.append("")
                report.append("**影响**: 前端无法连接后端 API，系统功能不可用")
                report.append("")
                report.append("**建议**:")
                report.append("1. 检查后端服务是否运行")
                report.append("2. 检查 nginx proxy_pass 配置")
                report.append("3. 检查防火墙/安全组规则")
                report.append("")
                
                # 添加为安全问题
                results['vulnerabilities'].insert(0, {
                    'type': 'Backend API Unreachable / nginx fallback',
                    'severity': 'HIGH',
                    'endpoint': 'Multiple paths',
                    'evidence': f'{html_fallback} paths return HTML fallback instead of JSON API'
                })
            elif real_api > 0:
                report.append("**状态**: 发现可访问的 JSON API 端点")
                report.append("")
        
        # 漏洞详情
        if results.get('vulnerabilities'):
            report.append("## 漏洞详情")
            report.append("")
            
            # 按严重程度分组
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            vulns_by_severity = {s: [] for s in severity_order}
            
            for v in results['vulnerabilities']:
                sev = v.get('severity', 'INFO').upper()
                if sev in vulns_by_severity:
                    vulns_by_severity[sev].append(v)
                else:
                    vulns_by_severity['INFO'].append(v)
            
            for severity in severity_order:
                vulns = vulns_by_severity[severity]
                if vulns:
                    report.append(f"### {severity} ({len(vulns)})")
                    report.append("")
                    for v in vulns:
                        report.append(f"#### {v.get('type', 'Unknown')}")
                        report.append(f"- **端点**: {v.get('endpoint', 'N/A')}")
                        report.append(f"- **证据**: {v.get('evidence', 'N/A')}")
                        if v.get('payload'):
                            report.append(f"- **Payload**: `{v.get('payload')}`")
                        report.append("")
        
        # 云存储发现
        if results.get('cloud_findings'):
            report.append("## 云存储发现")
            report.append("")
            for f in results['cloud_findings']:
                report.append(f"- {f.get('type')}: {f.get('evidence')}")
            report.append("")
        
        # 端点列表
        if results.get('endpoints'):
            report.append("## API 端点列表")
            report.append("")
            report.append(f"共发现 {len(results['endpoints'])} 个端点")
            report.append("")
            
            for ep in results['endpoints'][:50]:
                report.append(f"- `{ep.get('method', 'GET')}` {ep.get('path', ep.get('url', ''))} ({ep.get('source', '')})")
            
            if len(results['endpoints']) > 50:
                report.append(f"- ... 还有 {len(results['endpoints']) - 50} 个端点")
            report.append("")
        
        return "\n".join(report)


def run_skill(target: str) -> Dict:
    """
    执行完整的 SKILL.md 测试流程
    
    使用 TestContext 在模块间共享数据，实现模块联动
    """
    print("=" * 70)
    print("  API Security Testing Skill")
    print("=" * 70)
    print()
    
    # 创建测试上下文
    ctx = TestContext(target=target)
    
    # 阶段 0: 前置检查
    if not PrerequisiteChecker.check(ctx):
        print("[FATAL] 前置检查失败")
        return {'error': '前置检查失败', 'target': target}
    
    start_time = time.time()
    
    # 阶段 1: 资产发现 (联动)
    discovery = AssetDiscovery(ctx)
    discovery.run()
    
    # 阶段 2: 漏洞分析
    print("[2] 漏洞分析")
    print("-" * 70)
    tester = VulnerabilityTester(ctx)
    tester.run()
    
    # 阶段 2.5: Fuzzing
    print("[2.5] API Fuzzing")
    print("-" * 70)
    _run_fuzzing(ctx)
    
    # 阶段 3: 云存储测试
    print("[3] 云存储测试")
    print("-" * 70)
    cloud_tester = CloudStorageTester(ctx.target, ctx.session)
    ctx.cloud_findings = cloud_tester.run()
    
    # 更新上下文时间
    ctx.duration = time.time() - start_time
    
    # 阶段 4: 报告生成
    print("[4] 生成报告")
    print("-" * 70)
    
    report = ReportGenerator.generate(ctx.__dict__)
    print(report)
    
    report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_dir = os.path.dirname(report_file)
    if report_dir and not os.path.exists(report_dir):
        os.makedirs(report_dir, exist_ok=True)
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n报告已保存: {report_file}")
    
    return vars(ctx)


def _run_fuzzing(ctx: TestContext):
    """执行 Fuzzing（使用上下文）"""
    try:
        from core.api_parser import APIFuzzer, ParsedEndpoint, APIParam, ParamType, ParamLocation
        
        parsed_eps = []
        for ep_data in ctx.get_all_endpoints():
            ep = ParsedEndpoint(
                path=ep_data.get('path', ''),
                method=ep_data.get('method', 'GET'),
                source=ep_data.get('source', ''),
                semantic_type=ep_data.get('semantic_type', ''),
            )
            params = ep_data.get('params', {})
            if isinstance(params, dict):
                for p_name, p_val in params.items():
                    ep.params.append(APIParam(
                        name=p_name,
                        param_type=ParamType.QUERY,
                        location=ParamLocation.URL,
                        required=False,
                    ))
            elif isinstance(params, list):
                for p in params:
                    if isinstance(p, dict) and 'name' in p:
                        ep.params.append(APIParam(
                            name=p['name'],
                            param_type=ParamType.QUERY,
                            location=ParamLocation.URL,
                            required=p.get('required', False),
                        ))
            parsed_eps.append(ep)
        
        fuzzer = APIFuzzer(ctx.target, ctx.session)
        fuzz_results = fuzzer.fuzz_endpoints(parsed_eps, ctx.parent_paths)
        
        for vuln in fuzz_results:
            ctx.add_vulnerability(vuln)
        
        print(f"  [Fuzzing] 发现 {len(fuzz_results)} 个问题")
        
    except Exception as e:
        print(f"  [WARN] Fuzzing 失败: {e}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='API Security Testing Skill')
    parser.add_argument('target', help='目标 URL')
    args = parser.parse_args()
    
    target = args.target
    if not target.startswith('http'):
        target = 'http://' + target
    
    run_skill(target)
