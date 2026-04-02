#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SKILL.md 的完整可执行实现

完整测试流程:
- 阶段 0: 前置检查 (依赖检查)
- 阶段 1: 资产发现 (端点、JS、SPA)
- 阶段 2: 多维度漏洞分析
  - 2.1 SQL注入/XSS/路径遍历测试
  - 2.3 GraphQL 专项测试
  - 2.4 IDOR/越权测试
  - 2.5 暴力破解测试
  - 2.6 WebSocket 测试
- 阶段 3: 云存储安全测试
- 阶段 4: 报告生成

使用方式:
    python3 -m core.runner http://target.com
    
    from core.runner import run_skill
    result = run_skill('http://target.com')
"""

import sys
import re
import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

sys.path.insert(0, '/workspace/skill-play/API-Security-Testing-Optimized')

logger = logging.getLogger(__name__)


class PrerequisiteChecker:
    """阶段 0: 前置检查"""
    
    @staticmethod
    def check() -> bool:
        """检查所有依赖"""
        print("[0] 前置检查")
        print("-" * 70)
        
        results = {}
        
        # playwright
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                browser.close()
            results['playwright'] = True
            print("  [OK] playwright")
        except Exception as e:
            results['playwright'] = False
            print(f"  [FAIL] playwright: {e}")
            print("  [TRY] 尝试修复...")
            if PrerequisiteChecker.fix_playwright():
                results['playwright'] = True
                print("  [OK] playwright 修复成功")
        
        # requests
        try:
            import requests
            results['requests'] = True
            print("  [OK] requests")
        except ImportError:
            results['requests'] = False
            print("  [FAIL] requests")
        
        print()
        return results.get('playwright', False) and results.get('requests', False)
    
    @staticmethod
    def fix_playwright():
        """修复 playwright"""
        import subprocess
        try:
            subprocess.run(['playwright', 'install-deps', 'chromium'], 
                          capture_output=True, timeout=120)
            subprocess.run(['playwright', 'install', 'chromium'], 
                          capture_output=True, timeout=120)
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                browser.close()
            return True
        except:
            return False


class AssetDiscovery:
    """阶段 1: 资产发现 (增强版)"""
    
    def __init__(self, target: str, session):
        self.target = target
        self.session = session
        self.endpoints = []
        self.js_files = []
        self.tech_stack = {}
        self.parent_paths = {}
        self.api_parser = None
    
    def run(self) -> Dict:
        """执行资产发现"""
        print("[1] 资产发现")
        print("-" * 70)
        
        # 1.1 目标探测
        self._probe_target()
        
        # 1.2 使用增强版 API 解析器
        self._parse_endpoints_with_api_parser()
        
        # 1.3 父路径探测
        self._probe_parent_paths()
        
        print(f"\n  发现端点: {len(self.endpoints)}")
        print(f"  父路径: {len(self.parent_paths)}")
        print(f"  技术栈: {self.tech_stack}")
        print()
        
        return {
            'endpoints': self.endpoints,
            'js_files': self.js_files,
            'tech_stack': self.tech_stack,
            'parent_paths': self.parent_paths,
        }
    
    def _probe_target(self):
        """基础探测"""
        try:
            r = self.session.get(self.target, timeout=10)
            
            server = r.headers.get('Server', 'Unknown')
            print(f"  Server: {server}")
            
            html = r.text.lower()
            if 'vue' in html:
                self.tech_stack['frontend'] = 'Vue.js'
            if 'react' in html:
                self.tech_stack['frontend'] = 'React'
            if 'jquery' in html:
                self.tech_stack['jquery'] = True
            if 'element' in html:
                self.tech_stack['ui'] = 'ElementUI'
            if 'angular' in html:
                self.tech_stack['frontend'] = 'Angular'
            
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
    
    def _parse_endpoints_with_api_parser(self):
        """使用增强版 API 解析器"""
        try:
            from core.api_parser import APIEndpointParser
            
            self.api_parser = APIEndpointParser(self.target, self.session)
            js_files = self.api_parser.discover_js_files()
            self.js_files = js_files
            print(f"  发现 JS 文件: {len(js_files)}")
            
            # 解析端点
            parsed_endpoints = self.api_parser.parse_js_files(js_files)
            
            # 转换为字典格式
            for ep in parsed_endpoints:
                self.endpoints.append({
                    'path': ep.path,
                    'method': ep.method,
                    'params': [{'name': p.name, 'type': p.param_type.value, 'required': p.required} for p in ep.params],
                    'source': ep.source,
                    'semantic_type': ep.semantic_type,
                    'has_params': ep.has_params(),
                })
            
            # 打印摘要
            if self.api_parser:
                summary = self.api_parser.get_endpoints_summary()
                for line in summary.split('\n'):
                    if line.strip():
                        print(f"  {line}")
            
            # 总是尝试动态分析来验证静态发现
            print(f"\n  [动态分析] 启动动态分析验证...")
            self._run_dynamic_analysis()
            
        except Exception as e:
            print(f"  [WARN] API 解析器失败: {e}")
            # 回退到旧方法
            self._fallback_js_analysis()
    
    def _run_dynamic_analysis(self):
        """运行动态 API 分析"""
        try:
            from core.dynamic_api_analyzer import DynamicAPIAnalyzer
            
            analyzer = DynamicAPIAnalyzer(self.target)
            
            # 执行动态分析
            results = analyzer.analyze_full(max_requests=100)
            
            # 合并动态发现的端点
            dynamic_endpoints = results.get('endpoints', [])
            print(f"  [动态分析] 发现 {len(dynamic_endpoints)} 个端点")
            
            for ep in dynamic_endpoints:
                # 检查是否已存在
                path = ep.get('path', '')
                method = ep.get('method', 'GET')
                
                exists = any(
                    e.get('path') == path and e.get('method') == method
                    for e in self.endpoints
                )
                
                if not exists and path:
                    # params 可能是列表或字典
                    params_data = ep.get('params', [])
                    if isinstance(params_data, list):
                        params_dict = {p: True for p in params_data}
                    else:
                        params_dict = params_data
                    
                    self.endpoints.append({
                        'path': path,
                        'method': method,
                        'params': params_dict,
                        'source': f"dynamic_{ep.get('source', 'unknown')}",
                        'semantic_type': self._infer_semantic_type(path),
                        'has_params': bool(params_dict),
                    })
                    print(f"  [动态] {method} {path}")
            
            # 更新摘要
            param_count = sum(1 for ep in self.endpoints if ep.get('has_params') and ep.get('params'))
            print(f"  [动态分析] 更新后带参数端点: {param_count}")
            
        except ImportError:
            print(f"  [动态分析] dynamic_api_analyzer 不可用")
        except Exception as e:
            print(f"  [动态分析] 失败: {e}")
    
    def _fallback_js_analysis(self):
        """回退到 V35JSAnalyzer"""
        try:
            from core.deep_api_tester_v55 import V35JSAnalyzer
            
            js_analyzer = V35JSAnalyzer(self.target, self.session)
            
            for js_url in self.js_files:
                result = js_analyzer.analyze_js(js_url)
                
                for ep in result['endpoints']:
                    path = ep.url.replace(self.target.rstrip('/'), '')
                    self.endpoints.append({
                        'path': path,
                        'method': ep.method,
                        'params': [],
                        'source': f'v35js_{ep.discovered_by}',
                        'semantic_type': '',
                        'has_params': False,
                    })
            
            # 去重
            seen = set()
            unique = []
            for ep in self.endpoints:
                key = f"{ep['method']}:{ep['path']}"
                if key not in seen:
                    seen.add(key)
                    unique.append(ep)
            self.endpoints = unique
            
        except Exception as e:
            print(f"  [WARN] V35JSAnalyzer 也失败: {e}")
    
    def _probe_parent_paths(self):
        """探测父路径"""
        if not self.api_parser:
            return
        
        print(f"\n  [父路径探测] 开始探测...")
        
        self.parent_paths = self.api_parser.probe_parent_paths()
        
        # 统计可访问的 API 路径
        accessible = {k: v for k, v in self.parent_paths.items() if v.get('is_api')}
        print(f"  [父路径探测] 发现 {len(accessible)} 个可访问的 API 路径")


class VulnerabilityTester:
    """阶段 2: 多维度漏洞分析"""
    
    def __init__(self, target: str, session, endpoints: List):
        self.target = target
        self.session = session
        self.endpoints = endpoints
        self.vulnerabilities = []
    
    def run(self) -> List:
        """执行漏洞测试"""
        print("[2] 多维度漏洞分析")
        print("-" * 70)
        
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
        
        print(f"\n  发现漏洞: {len(self.vulnerabilities)}")
        print()
        
        return self.vulnerabilities
    
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
                    
                    sqli_indicators = ['sql', 'syntax', 'mysql', 'oracle', 'error', 'sqlite']
                    if any(ind in r.text.lower() for ind in sqli_indicators):
                        self.vulnerabilities.append({
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
                        self.vulnerabilities.append({
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
                        self.vulnerabilities.append({
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
                            self.vulnerabilities.append({
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
                        self.vulnerabilities.append({
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
                    self.vulnerabilities.append({
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
                        self.vulnerabilities.append({
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
                        self.vulnerabilities.append({
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
    
    Args:
        target: 目标 URL
    
    Returns:
        测试结果字典
    """
    print("=" * 70)
    print("  API Security Testing Skill")
    print("=" * 70)
    print()
    
    results = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'endpoints': [],
        'vulnerabilities': [],
        'cloud_findings': [],
        'tech_stack': {},
    }
    
    # 导入 requests
    import requests
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    # 阶段 0: 前置检查
    if not PrerequisiteChecker.check():
        print("[FATAL] 前置检查失败")
        results['error'] = '前置检查失败'
        return results
    
    start_time = time.time()
    
    # 阶段 1: 资产发现
    discovery = AssetDiscovery(target, session)
    disc_results = discovery.run()
    results['endpoints'] = disc_results['endpoints']
    results['tech_stack'] = disc_results['tech_stack']
    results['parent_paths'] = disc_results.get('parent_paths', {})
    
    # 阶段 2: 漏洞分析
    tester = VulnerabilityTester(target, session, results['endpoints'])
    results['vulnerabilities'] = tester.run()
    
    # 阶段 2.5: Fuzzing (增强版)
    print("[2.5] API Fuzzing")
    print("-" * 70)
    try:
        from core.api_parser import APIEndpointParser, APIFuzzer, ParsedEndpoint, APIParam, ParamType, ParamLocation
        
        # 转换端点格式
        parsed_eps = []
        for ep_data in results['endpoints']:
            ep = ParsedEndpoint(
                path=ep_data['path'],
                method=ep_data.get('method', 'GET'),
                source=ep_data.get('source', ''),
                semantic_type=ep_data.get('semantic_type', ''),
            )
            for p in ep_data.get('params', []):
                ep.params.append(APIParam(
                    name=p['name'],
                    param_type=ParamType(p.get('type', 'path')),
                    location=ParamLocation.URL,
                    required=p.get('required', True)
                ))
            parsed_eps.append(ep)
        
        # 执行 fuzzing
        fuzzer = APIFuzzer(target, session)
        fuzz_results = fuzzer.fuzz_endpoints(parsed_eps, results.get('parent_paths', {}))
        
        # 合并 fuzzing 结果
        results['vulnerabilities'].extend(fuzz_results)
        print(f"  [Fuzzing] 发现 {len(fuzz_results)} 个问题")
        
    except Exception as e:
        print(f"  [WARN] Fuzzing 失败: {e}")
    print()
    
    # 阶段 3: 云存储测试
    cloud_tester = CloudStorageTester(target, session)
    results['cloud_findings'] = cloud_tester.run()
    
    results['duration'] = time.time() - start_time
    
    # 阶段 4: 报告生成
    print("[4] 生成报告")
    print("-" * 70)
    
    report = ReportGenerator.generate(results)
    print(report)
    
    # 保存报告
    report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n报告已保存: {report_file}")
    results['report_file'] = report_file
    
    return results


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='API Security Testing Skill')
    parser.add_argument('target', help='目标 URL')
    args = parser.parse_args()
    
    target = args.target
    if not target.startswith('http'):
        target = 'http://' + target
    
    run_skill(target)
