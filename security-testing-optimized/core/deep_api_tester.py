#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深度 API 渗透测试引擎 v3.0
- 使用 Playwright 无头浏览器
- 拦截所有 XHR/Fetch 请求
- 从 JS 文件提取 API 端点
- 智能漏洞扫描
"""

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from urllib.parse import urljoin, urlparse
import requests
import re
import json
import time
from collections import defaultdict
from typing import Dict, List, Set

class DeepAPITester:
    """深度 API 测试引擎"""
    
    def __init__(self, target: str, headless: bool = True):
        self.target = target.rstrip('/')
        self.headless = headless
        self.api_endpoints = []
        self.js_files = []
        self.secrets = []
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def crawl_with_browser(self) -> List[Dict]:
        """使用无头浏览器爬取，拦截所有 API 请求"""
        print(f"\n{'='*60}")
        print(f"[+] 使用无头浏览器爬取：{self.target}")
        print(f"{'='*60}\n")
        
        api_requests = []
        
        with sync_playwright() as p:
            # 启动浏览器
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080}
            )
            page = context.new_page()
            
            # 拦截请求
            def handle_request(request):
                url = request.url
                method = request.method
                
                # 只记录 API 相关请求
                if self._is_api_url(url):
                    api_requests.append({
                        'url': url,
                        'method': method,
                        'resource_type': request.resource_type,
                        'headers': dict(request.headers),
                        'post_data': request.post_data
                    })
                    print(f"  [API] {method} {url}")
            
            page.on('request', handle_request)
            
            try:
                # 访问目标页面
                print(f"[*] 访问目标页面...")
                page.goto(self.target, wait_until='networkidle', timeout=30000)
                
                # 等待 JS 执行
                print(f"[*] 等待 JS 执行...")
                page.wait_for_timeout(5000)
                
                # 点击所有按钮和链接
                print(f"[*] 探索页面交互...")
                self._interact_with_page(page)
                
                # 提取 JS 文件
                print(f"[*] 提取 JS 文件...")
                self.js_files = self._extract_js_files(page)
                
                # 执行 JS 提取路由
                print(f"[*] 提取前端路由...")
                routes = self._extract_routes_from_js(page)
                
            except PlaywrightTimeout:
                print(f"[!] 页面加载超时")
            except Exception as e:
                print(f"[!] 错误：{e}")
            finally:
                browser.close()
        
        self.api_endpoints = api_requests
        return api_requests
    
    def _is_api_url(self, url: str) -> bool:
        """判断是否是 API 请求"""
        api_indicators = [
            '/api/', '/api/v', '/rest/', '/graphql',
            '/service/', '/do/', '/action/',
            '.json', '.action', '.do',
            'controller', 'service', 'api'
        ]
        return any(indicator in url.lower() for indicator in api_indicators)
    
    def _interact_with_page(self, page):
        """与页面交互，触发更多 API 请求"""
        # 点击所有按钮
        buttons = page.query_selector_all('button, input[type="button"], .btn')
        for btn in buttons[:10]:  # 限制数量
            try:
                btn.click()
                page.wait_for_timeout(1000)
            except:
                pass
        
        # 点击所有链接
        links = page.query_selector_all('a[href^="/"], a[href^="http"]')
        for link in links[:10]:
            try:
                link.click()
                page.wait_for_timeout(1000)
            except:
                pass
        
        # 滚动页面
        page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
        page.wait_for_timeout(2000)
        page.evaluate('window.scrollTo(0, 0)')
    
    def _extract_js_files(self, page) -> List[str]:
        """提取所有 JS 文件"""
        js_files = page.evaluate("""
            () => {
                const scripts = document.querySelectorAll('script[src]');
                return Array.from(scripts).map(s => s.src);
            }
        """)
        print(f"  [+] 发现 {len(js_files)} 个 JS 文件")
        return js_files
    
    def _extract_routes_from_js(self, page) -> List[str]:
        """从 JS 中提取路由"""
        routes = page.evaluate("""
            () => {
                const routes = [];
                
                // Vue Router
                if (window.$router && window.$router.options) {
                    window.$router.options.routes.forEach(route => {
                        routes.push(route.path);
                        if (route.children) {
                            route.children.forEach(child => routes.push(child.path));
                        }
                    });
                }
                
                return routes;
            }
        """)
        
        # 从 JS 文件内容提取
        for js_url in self.js_files[:5]:  # 限制数量
            try:
                response = self.session.get(js_url, timeout=10)
                content = response.text
                
                # 提取 API 端点
                api_patterns = [
                    r'axios\.(get|post|put|delete)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                    r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                    r'[\'"`](/api/[^\'"`]+)[\'"`]',
                    r'[\'"`](/rest/[^\'"`]+)[\'"`]',
                ]
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        endpoint = match[1] if isinstance(match, tuple) else match
                        if endpoint.startswith('/'):
                            routes.append(endpoint)
                            print(f"  [API] 从 JS 发现：{endpoint}")
                
            except Exception as e:
                pass
        
        return list(set(routes))
    
    def analyze_js_files(self):
        """分析 JS 文件，提取敏感信息"""
        print(f"\n{'='*60}")
        print(f"[+] 分析 JS 文件")
        print(f"{'='*60}\n")
        
        for js_url in self.js_files:
            try:
                response = self.session.get(js_url, timeout=10)
                content = response.text
                
                # 提取敏感信息
                secrets = self._extract_secrets(content, js_url)
                if secrets:
                    self.secrets.extend(secrets)
                
                # 提取 API 端点
                endpoints = self._extract_endpoints_from_js(content, js_url)
                if endpoints:
                    print(f"  [+] 从 {js_url} 发现 {len(endpoints)} 个端点")
                
            except Exception as e:
                print(f"  [!] 分析失败：{js_url} - {e}")
    
    def _extract_secrets(self, content: str, source: str) -> List[Dict]:
        """提取敏感信息"""
        secrets = []
        
        patterns = {
            'api_key': r'(?:api[_-]?key|apikey)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            'token': r'(?:token|auth[_-]?token)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            'password': r'(?:password|passwd|pwd)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            'secret': r'(?:secret|secret[_-]?key)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
        }
        
        for secret_type, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                secrets.append({
                    'type': secret_type,
                    'value': match[:50] + '...' if len(match) > 50 else match,
                    'source': source
                })
                print(f"  [!] 发现敏感信息 [{secret_type}]: {match[:20]}...")
        
        return secrets
    
    def _extract_endpoints_from_js(self, content: str, source: str) -> List[str]:
        """从 JS 内容提取端点"""
        endpoints = []
        
        patterns = [
            r'axios\.(get|post|put|delete)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'[\'"`](/api/[^\'"`]+)[\'"`]',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                endpoint = match[1] if isinstance(match, tuple) else match
                if endpoint.startswith('/'):
                    endpoints.append(endpoint)
        
        return endpoints
    
    def scan_vulnerabilities(self):
        """扫描漏洞"""
        print(f"\n{'='*60}")
        print(f"[+] 漏洞扫描")
        print(f"{'='*60}\n")
        
        # 去重端点
        unique_endpoints = defaultdict(set)
        for req in self.api_endpoints:
            parsed = urlparse(req['url'])
            unique_endpoints[parsed.path].add(req['method'])
        
        # SQL 注入测试
        print(f"[*] SQL 注入测试...")
        self._test_sqli(unique_endpoints)
        
        # XSS 测试
        print(f"[*] XSS 测试...")
        self._test_xss(unique_endpoints)
        
        # 未授权访问测试
        print(f"[*] 未授权访问测试...")
        self._test_unauthorized_access(unique_endpoints)
        
        # 敏感信息泄露
        print(f"[*] 敏感信息泄露测试...")
        self._test_data_exposure(unique_endpoints)
    
    def _test_sqli(self, endpoints: Dict[str, Set[str]]):
        """SQL 注入测试"""
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--"
        ]
        
        sqli_errors = [
            'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
            'SQLite', 'ODBC', 'jdbc', 'hibernate', 'sqlserver'
        ]
        
        for path, methods in endpoints.items():
            for method in methods:
                for payload in sqli_payloads:
                    try:
                        test_url = f"{self.target}{path}"
                        params = {'id': payload, 'search': payload, 'user': payload}
                        
                        if method == 'GET':
                            response = self.session.get(test_url, params=params, timeout=10)
                        else:
                            response = self.session.post(test_url, data=params, timeout=10)
                        
                        # 检测 SQL 错误
                        for error in sqli_errors:
                            if error.lower() in response.text.lower():
                                self.vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'severity': 'CRITICAL',
                                    'endpoint': path,
                                    'method': method,
                                    'payload': payload,
                                    'evidence': error
                                })
                                print(f"  [!] SQL 注入发现：{path}")
                                break
                    
                    except Exception as e:
                        pass
    
    def _test_xss(self, endpoints: Dict[str, Set[str]]):
        """XSS 测试"""
        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>'
        ]
        
        for path, methods in endpoints.items():
            for payload in xss_payloads:
                try:
                    test_url = f"{self.target}{path}"
                    params = {'q': payload, 'search': payload, 'name': payload}
                    
                    response = self.session.get(test_url, params=params, timeout=10)
                    
                    # 检测 payload 是否被反射
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'XSS (Reflected)',
                            'severity': 'HIGH',
                            'endpoint': path,
                            'payload': payload,
                            'evidence': 'Payload reflected in response'
                        })
                        print(f"  [!] XSS 发现：{path}")
                
                except:
                    pass
    
    def _test_unauthorized_access(self, endpoints: Dict[str, Set[str]]):
        """未授权访问测试"""
        sensitive_paths = ['/admin', '/api/user', '/api/config', '/api/admin']
        
        for path in sensitive_paths:
            if path in endpoints:
                try:
                    test_url = f"{self.target}{path}"
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Unauthorized Access',
                            'severity': 'HIGH',
                            'endpoint': path,
                            'evidence': f'Status: {response.status_code}'
                        })
                        print(f"  [!] 未授权访问：{path}")
                
                except:
                    pass
    
    def _test_data_exposure(self, endpoints: Dict[str, Set[str]]):
        """敏感数据暴露测试"""
        for path, methods in endpoints.items():
            try:
                test_url = f"{self.target}{path}"
                response = self.session.get(test_url, timeout=10)
                
                # 检查响应中是否包含敏感信息
                sensitive_patterns = {
                    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                    'phone': r'\b1[3-9]\d{9}\b',
                    'id_card': r'\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b',
                    'password': r'password["\']?\s*[:=]\s*["\']?[^"\',\s]+'
                }
                
                for data_type, pattern in sensitive_patterns.items():
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'type': 'Sensitive Data Exposure',
                            'severity': 'MEDIUM',
                            'endpoint': path,
                            'data_type': data_type,
                            'evidence': f'Found {data_type} in response'
                        })
                        print(f"  [!] 敏感数据暴露 [{data_type}]: {path}")
            
            except:
                pass
    
    def generate_report(self, output_file: str = 'report.md'):
        """生成测试报告"""
        report = f"""# 深度 API 渗透测试报告

## 执行摘要
- **测试目标**: {self.target}
- **测试时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}
- **测试工具**: Deep API Tester v3.0

## 发现统计
- API 端点：{len(self.api_endpoints)}
- JS 文件：{len(self.js_files)}
- 敏感信息：{len(self.secrets)}
- 漏洞数量：{len(self.vulnerabilities)}

## API 端点列表
"""
        
        # 端点列表
        endpoints_summary = defaultdict(set)
        for req in self.api_endpoints:
            parsed = urlparse(req['url'])
            endpoints_summary[parsed.path].add(req['method'])
        
        for path, methods in sorted(endpoints_summary.items()):
            report += f"- `{', '.join(methods)} {path}`\n"
        
        # 漏洞详情
        report += f"\n## 漏洞详情\n"
        
        if self.vulnerabilities:
            for vuln in self.vulnerabilities:
                report += f"""
### {vuln['type']}
- **严重程度**: {vuln['severity']}
- **端点**: {vuln['endpoint']}
- **方法**: {vuln.get('method', 'N/A')}
- **证据**: {vuln.get('evidence', 'N/A')}
"""
        else:
            report += "\n未发现明显漏洞。\n"
        
        # 敏感信息
        if self.secrets:
            report += f"\n## 敏感信息\n"
            for secret in self.secrets:
                report += f"- [{secret['type']}] {secret['source']}: {secret['value']}\n"
        
        # 保存报告
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"\n[+] 报告已保存：{output_file}")
        return report
    
    def run_full_test(self, output_file: str = 'report.md'):
        """执行完整测试流程"""
        print(f"\n{'='*60}")
        print(f"深度 API 渗透测试 v3.0")
        print(f"目标：{self.target}")
        print(f"{'='*60}\n")
        
        # 1. 浏览器爬取
        self.crawl_with_browser()
        
        # 2. JS 分析
        self.analyze_js_files()
        
        # 3. 漏洞扫描
        self.scan_vulnerabilities()
        
        # 4. 生成报告
        self.generate_report(output_file)
        
        print(f"\n{'='*60}")
        print(f"测试完成！")
        print(f"发现 {len(self.vulnerabilities)} 个漏洞")
        print(f"{'='*60}\n")
        
        return {
            'endpoints': len(self.api_endpoints),
            'js_files': len(self.js_files),
            'secrets': len(self.secrets),
            'vulnerabilities': len(self.vulnerabilities)
        }


# CLI 入口
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python deep_api_tester.py <target_url> [output_file]")
        print("Example: python deep_api_tester.py http://example.com report.md")
        sys.exit(1)
    
    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else 'report.md'
    
    tester = DeepAPITester(target)
    tester.run_full_test(output)
