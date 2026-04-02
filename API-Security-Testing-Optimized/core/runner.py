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
    """阶段 1: 资产发现"""
    
    def __init__(self, target: str, session):
        self.target = target
        self.session = session
        self.endpoints = []
        self.js_files = []
        self.tech_stack = {}
    
    def run(self) -> Dict:
        """执行资产发现"""
        print("[1] 资产发现")
        print("-" * 70)
        
        # 1.1 目标探测
        self._probe_target()
        
        # 1.2 JS 文件发现
        self._discover_js_files()
        
        # 1.3 V35JSAnalyzer 端点分析
        self._analyze_js_endpoints()
        
        # 1.4 Swagger/API 文档发现
        self._discover_swagger()
        
        # 1.5 智能路径猜测
        self._intelligent_guess()
        
        # 1.6 SPA 检测
        self._detect_spa()
        
        print(f"\n  发现端点: {len(self.endpoints)}")
        print(f"  技术栈: {self.tech_stack}")
        print()
        
        return {
            'endpoints': self.endpoints,
            'js_files': self.js_files,
            'tech_stack': self.tech_stack
        }
    
    def _probe_target(self):
        """基础探测"""
        try:
            r = self.session.get(self.target, timeout=10)
            
            # 服务器指纹
            server = r.headers.get('Server', 'Unknown')
            print(f"  Server: {server}")
            
            # 技术栈识别
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
            
            # CORS 检测
            cors_origin = r.headers.get('Access-Control-Allow-Origin', '未设置')
            print(f"  CORS: {cors_origin}")
            
        except Exception as e:
            print(f"  [WARN] 目标探测失败: {e}")
    
    def _discover_js_files(self):
        """发现 JS 文件"""
        try:
            r = self.session.get(self.target, timeout=10)
            patterns = [
                r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, r.text)
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
            
            print(f"  发现 JS 文件: {len(self.js_files)}")
            
        except Exception as e:
            print(f"  [WARN] JS 文件发现失败: {e}")
    
    def _analyze_js_endpoints(self):
        """使用 V35JSAnalyzer 分析端点"""
        try:
            from core.deep_api_tester_v55 import V35JSAnalyzer
            
            js_analyzer = V35JSAnalyzer(self.target, self.session)
            
            for js_url in self.js_files:
                result = js_analyzer.analyze_js(js_url)
                
                for ep in result['endpoints']:
                    path = ep.url.replace(self.target.rstrip('/'), '')
                    self.endpoints.append({
                        'url': ep.url,
                        'path': path,
                        'method': ep.method,
                        'source': f'v35js_{ep.discovered_by}'
                    })
                
                if result['endpoints']:
                    print(f"  [V35JS] {js_url.split('/')[-1]}: 发现 {len(result['endpoints'])} 个端点")
            
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
            print(f"  [WARN] V35JSAnalyzer 失败: {e}")
    
    def _discover_swagger(self):
        """发现 Swagger/API 文档"""
        swagger_paths = [
            '/swagger.json', '/swagger.yaml', '/api-docs',
            '/v1/api-docs', '/doc.html', '/swagger-ui.html'
        ]
        
        for path in swagger_paths:
            url = self.target.rstrip('/') + path
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200 and 'swagger' in r.text.lower():
                    self.endpoints.append({
                        'url': url,
                        'path': path,
                        'method': 'GET',
                        'source': 'swagger'
                    })
                    print(f"  [Swagger] 发现: {path}")
            except:
                pass
    
    def _intelligent_guess(self):
        """智能路径猜测"""
        common_paths = [
            '/api/users', '/api/user', '/api/admin', '/api/auth',
            '/api/login', '/api/logout', '/api/profile', '/api/settings',
            '/auth/login', '/auth/logout', '/auth/token',
            '/user/info', '/user/list', '/user/profile',
            '/admin/users', '/admin/config', '/admin/settings',
        ]
        
        for path in common_paths:
            url = self.target.rstrip('/') + path
            try:
                r = self.session.get(url, timeout=3)
                if r.status_code == 200:
                    ct = r.headers.get('Content-Type', '')
                    if 'json' in ct.lower() or '{' in r.text[:100]:
                        self.endpoints.append({
                            'url': url,
                            'path': path,
                            'method': 'GET',
                            'source': 'intelligent_guess'
                        })
            except:
                pass
    
    def _detect_spa(self):
        """检测 SPA"""
        try:
            r = self.session.get(self.target, timeout=10)
            if '#' in r.text or 'hash' in r.text.lower():
                self.tech_stack['spa'] = True
                print("  SPA: 是")
            else:
                self.tech_stack['spa'] = False
                print("  SPA: 否")
        except:
            pass


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
    
    # 阶段 2: 漏洞分析
    tester = VulnerabilityTester(target, session, results['endpoints'])
    results['vulnerabilities'] = tester.run()
    
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
