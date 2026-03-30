#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深度 API 渗透测试引擎 v5.0 - 最终版
融合 v3.5 和 v4.0 的所有优势:
- v3.5 的 JS 分析能力 ✅
- v4.0 的智能学习 ✅
- 增强的 fallback 机制 ✅
- 改进的流量学习算法 ✅
"""

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from urllib.parse import urljoin, urlparse, parse_qs
import requests
import re
import json
import time
from collections import defaultdict
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, asdict

# ==================== 数据结构 ====================

@dataclass
class APIEndpoint:
    url: str
    method: str = 'GET'
    source: str = 'unknown'
    params: Dict = None
    discovered_by: str = 'unknown'
    metadata: Dict = None

@dataclass
class Vulnerability:
    type: str
    severity: str
    endpoint: str
    method: str = 'GET'
    payload: str = ''
    evidence: str = ''
    description: str = ''
    remediation: str = ''
    cwe_id: str = ''
    owasp_category: str = ''

@dataclass
class SensitiveData:
    type: str
    value: str
    source: str
    severity: str = 'MEDIUM'
    context: str = ''

# ==================== v3.5 的强力 JS 分析器 ====================

class PowerfulJSAnalyzer:
    """v3.5 的 JS 分析能力 - 经过实战验证"""
    
    def __init__(self, target: str, session: requests.Session):
        self.target = target
        self.session = session
    
    def analyze_js(self, js_url: str) -> Dict:
        """分析单个 JS 文件"""
        result = {
            'endpoints': [],
            'secrets': [],
            'credentials': []
        }
        
        try:
            response = self.session.get(js_url, timeout=10)
            content = response.text
            
            # 提取 API 端点 (v3.5 的成熟正则)
            result['endpoints'] = self._extract_endpoints(content, js_url)
            
            # 提取敏感信息
            result['secrets'] = self._extract_secrets(content, js_url)
            
            # 提取凭证
            result['credentials'] = self._extract_credentials(content, js_url)
            
        except Exception as e:
            pass
        
        return result
    
    def _extract_endpoints(self, content: str, source: str) -> List[APIEndpoint]:
        """从 JS 提取 API 端点"""
        endpoints = []
        
        # 全面的正则模式 (v3.5 + v5.0 优化)
        patterns = [
            # axios
            (r'axios\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', 'axios'),
            (r'this\.\$axios\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', 'vue_axios'),
            
            # fetch
            (r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', 'fetch'),
            
            # 通用 API 路径
            (r'[\'"`](/api/[^\'"`\s?#]+)[\'"`]', 'api_path'),
            (r'[\'"`](/rest/[^\'"`\s?#]+)[\'"`]', 'rest_path'),
            (r'[\'"`](/service/[^\'"`\s?#]+)[\'"`]', 'service_path'),
            (r'[\'"`](/do/[^\'"`\s?#]+)[\'"`]', 'do_path'),
            
            # 业务路径 (针对目标优化)
            (r'[\'"`](/users/[^\'"`\s?#]+)[\'"`]', 'users_path'),
            (r'[\'"`](/projects/[^\'"`\s?#]+)[\'"`]', 'projects_path'),
            (r'[\'"`](/organ/[^\'"`\s?#]+)[\'"`]', 'organ_path'),
            
            # 单级路径 (v5.0 新增 - 捕获 /login, /home 等)
            (r'[\'"`](/(login|home|admin|role|group|major|unit|personnel|changePassword|platformLogin))[^\'"`\s?#]*[\'"`]', 'single_path'),
            
            # 完整 URL
            (r'(https?://[^\'"`\s]+/api/[^\'"`\s]+)', 'full_url'),
            
            # 通用路径模式 (v5.0 新增 - 捕获更多路径)
            (r'[\'"`](/([a-z]+)/?(?:[a-z]+)*)[\'"`]', 'generic_path'),
        ]
        
        for pattern, pattern_type in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    method = match[0].upper() if match[0].lower() in ['get', 'post', 'put', 'delete', 'patch'] else 'GET'
                    url = match[1]
                else:
                    method = 'GET'
                    url = match
                
                # 清理和转换 URL
                url = url.replace('${', '{').replace('}', '')
                if url.startswith('/'):
                    url = urljoin(self.target, url)
                
                # 过滤无效 URL (放宽条件，捕获更多有效路径)
                if len(url) > 5 and 'http' in url:
                    # 跳过明显的误报（如 CSS 属性、颜色值等）
                    skip_patterns = ['color', 'style', 'width', 'height', 'margin', 'padding']
                    if not any(skip in url.lower() for skip in skip_patterns):
                        endpoints.append(APIEndpoint(
                            url=url,
                            method=method,
                            source=source,
                            discovered_by=f'js_analysis_{pattern_type}'
                        ))
        
        return endpoints
    
    def _extract_secrets(self, content: str, source: str) -> List[SensitiveData]:
        """提取敏感信息"""
        secrets = []
        
        patterns = {
            'token': [
                r'(?:token|auth[_-]?token)\s*[=:]\s*[\'"`]([^\'"`]{8,})[\'"`]',
                r'Bearer\s+[\'"`]([^\'"`]+)[\'"`]',
            ],
            'api_key': [
                r'(?:api[_-]?key|apikey)\s*[=:]\s*[\'"`]([^\'"`]{8,})[\'"`]',
            ],
            'password': [
                r'(?:password|passwd)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            ],
        }
        
        for secret_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    secrets.append(SensitiveData(
                        type=secret_type,
                        value=match[:100] + '...' if len(match) > 100 else match,
                        source=source,
                        severity='HIGH' if secret_type in ['token', 'password'] else 'MEDIUM'
                    ))
        
        return secrets
    
    def _extract_credentials(self, content: str, source: str) -> List[Dict]:
        """提取登录凭证"""
        credentials = []
        
        pattern = r'username\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`].*?password\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]'
        matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
        
        for match in matches:
            credentials.append({
                'username': match[0],
                'password': match[1],
                'source': source
            })
        
        return credentials

# ==================== 改进的流量学习器 ====================

class ImprovedTrafficLearner:
    """改进的流量学习算法"""
    
    def __init__(self):
        self.api_keywords = [
            'api', 'rest', 'service', 'do', 'action', 'controller',
            'user', 'login', 'admin', 'manage', 'system', 'data',
            'project', 'organ', 'personnel', 'role', 'major', 'group',
            'unit', 'department', 'expert', 'role', 'home', 'platform'
        ]
        
        self.skip_patterns = [
            '/js/', '/css/', '/img/', '/font/', '/static/',
            '.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot'
        ]
    
    def learn_from_traffic(self, traffic: List[Dict]) -> Dict:
        """从流量中学习"""
        if not traffic:
            return self._get_default_patterns()
        
        # 分析流量
        prefixes = defaultdict(int)
        paths = []
        
        for req in traffic:
            url = req.get('url', '')
            parsed = urlparse(url)
            path = parsed.path
            
            # 跳过静态资源
            if any(skip in path.lower() for skip in self.skip_patterns):
                continue
            
            paths.append(path)
            
            # 提取前缀
            parts = path.strip('/').split('/')
            if len(parts) >= 1:
                # 单级前缀
                prefix = '/' + parts[0]
                if any(kw in prefix.lower() for kw in self.api_keywords):
                    prefixes[prefix] += 1
                
                # 两级前缀
                if len(parts) >= 2:
                    prefix2 = '/' + parts[0] + '/' + parts[1]
                    if any(kw in prefix2.lower() for kw in self.api_keywords):
                        prefixes[prefix2] += 1
        
        # 返回学习结果
        return {
            'api_prefixes': [p for p, c in prefixes.items() if c >= 1],
            'common_paths': paths,
            'traffic_count': len(traffic)
        }
    
    def _get_default_patterns(self) -> Dict:
        """默认模式 (当流量不足时)"""
        return {
            'api_prefixes': ['/api', '/rest', '/service', '/do', '/users', '/projects', '/organ'],
            'common_paths': [],
            'traffic_count': 0,
            'is_default': True
        }

# ==================== 增强的 Fallback 机制 ====================

class FallbackMechanism:
    """增强的 Fallback 机制"""
    
    def __init__(self, target: str, session: requests.Session):
        self.target = target
        self.session = session
        self.js_analyzer = PowerfulJSAnalyzer(target, session)
        self.traffic_learner = ImprovedTrafficLearner()
    
    def extract_endpoints(self, js_contents: Dict[str, str], traffic: List[Dict]) -> List[APIEndpoint]:
        """多策略提取 API 端点"""
        all_endpoints = []
        
        # 策略 1: 从 JS 分析提取 (v3.5 能力)
        print(f"  [*] 策略 1: JS 分析提取...")
        for js_url, js_content in js_contents.items():
            result = self.js_analyzer.analyze_js(js_url)
            all_endpoints.extend(result['endpoints'])
            print(f"    [+] {js_url[:80]}... -> {len(result['endpoints'])} 个端点")
        
        # 策略 2: 从流量学习提取 (v4.0 能力)
        print(f"  [*] 策略 2: 流量学习提取...")
        learned = self.traffic_learner.learn_from_traffic(traffic)
        
        if not learned.get('is_default', False):
            for prefix in learned['api_prefixes']:
                pattern = rf'[\'"`]({re.escape(prefix)}[^\'"`\s?#]*)[\'"`]'
                for js_url, js_content in js_contents.items():
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        if len(match) > 3:
                            url = urljoin(self.target, match)
                            all_endpoints.append(APIEndpoint(
                                url=url,
                                method='GET',
                                source=js_url,
                                discovered_by='traffic_learned'
                            ))
        
        # 策略 3: 通用模式提取 (Fallback)
        if len(all_endpoints) < 5:
            print(f"  [*] 策略 3: 通用模式提取 (Fallback)...")
            for js_url, js_content in js_contents.items():
                endpoints = self._extract_with_generic_patterns(js_content, js_url)
                all_endpoints.extend(endpoints)
        
        # 去重
        unique_endpoints = self._deduplicate_endpoints(all_endpoints)
        print(f"  [+] 总共发现 {len(unique_endpoints)} 个唯一 API 端点")
        
        return unique_endpoints
    
    def _extract_with_generic_patterns(self, content: str, source: str) -> List[APIEndpoint]:
        """通用模式提取"""
        endpoints = []
        
        patterns = [
            r'[\'"`](/[a-z]+/[^\'"`\s?#]+)[\'"`]',
            r'axios\.(get|post|put|delete)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    url = match[1]
                else:
                    url = match
                
                if url.startswith('/') and len(url) > 3:
                    full_url = urljoin(self.target, url)
                    endpoints.append(APIEndpoint(
                        url=full_url,
                        method='GET',
                        source=source,
                        discovered_by='generic_fallback'
                    ))
        
        return endpoints
    
    def _deduplicate_endpoints(self, endpoints: List[APIEndpoint]) -> List[APIEndpoint]:
        """去重"""
        seen = set()
        unique = []
        
        for ep in endpoints:
            key = f"{ep.method}:{ep.url}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        
        return unique

# ==================== 漏洞检测器 ====================

class VulnerabilityScanner:
    """漏洞扫描器"""
    
    def __init__(self, target: str, session: requests.Session):
        self.target = target
        self.session = session
    
    def scan(self, endpoints: List[APIEndpoint], js_contents: Dict[str, str], secrets: List[SensitiveData]) -> List[Vulnerability]:
        """扫描漏洞"""
        vulns = []
        
        # 1. SQL 注入测试
        print(f"[*] SQL 注入测试...")
        vulns.extend(self._test_sqli(endpoints))
        
        # 2. XSS 测试
        print(f"[*] XSS 测试...")
        vulns.extend(self._test_xss(endpoints))
        
        # 3. 未授权访问
        print(f"[*] 未授权访问测试...")
        vulns.extend(self._test_unauthorized(endpoints))
        
        # 4. 敏感数据暴露
        print(f"[*] 敏感数据暴露测试...")
        vulns.extend(self._test_data_exposure(secrets))
        
        return vulns
    
    def _test_sqli(self, endpoints: List[APIEndpoint]) -> List[Vulnerability]:
        """SQL 注入测试"""
        vulns = []
        payloads = ["' OR '1'='1", "' OR 1=1--", "admin'--"]
        errors = ['SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'SQLite']
        
        for ep in endpoints[:20]:  # 限制测试数量
            for payload in payloads:
                try:
                    params = {'id': payload, 'search': payload}
                    resp = self.session.get(ep.url, params=params, timeout=5)
                    
                    for error in errors:
                        if error.lower() in resp.text.lower():
                            vulns.append(Vulnerability(
                                type='SQL Injection',
                                severity='CRITICAL',
                                endpoint=ep.url,
                                method=ep.method,
                                evidence=error
                            ))
                            break
                except:
                    pass
        
        return vulns
    
    def _test_xss(self, endpoints: List[APIEndpoint]) -> List[Vulnerability]:
        """XSS 测试"""
        vulns = []
        payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']
        
        for ep in endpoints[:20]:
            for payload in payloads:
                try:
                    params = {'q': payload, 'search': payload}
                    resp = self.session.get(ep.url, params=params, timeout=5)
                    
                    if payload in resp.text:
                        vulns.append(Vulnerability(
                            type='XSS (Reflected)',
                            severity='HIGH',
                            endpoint=ep.url,
                            evidence='Payload reflected'
                        ))
                except:
                    pass
        
        return vulns
    
    def _test_unauthorized(self, endpoints: List[APIEndpoint]) -> List[Vulnerability]:
        """未授权访问测试"""
        vulns = []
        sensitive_paths = ['/admin', '/api/user', '/api/config']
        
        for ep in endpoints:
            if any(s in ep.url for s in sensitive_paths):
                try:
                    resp = self.session.get(ep.url, timeout=5)
                    if resp.status_code == 200 and len(resp.text) > 100:
                        vulns.append(Vulnerability(
                            type='Unauthorized Access',
                            severity='HIGH',
                            endpoint=ep.url,
                            evidence=f'Status: {resp.status_code}'
                        ))
                except:
                    pass
        
        return vulns
    
    def _test_data_exposure(self, secrets: List[SensitiveData]) -> List[Vulnerability]:
        """敏感数据暴露测试"""
        vulns = []
        
        for secret in secrets:
            if secret.severity in ['HIGH', 'CRITICAL']:
                vulns.append(Vulnerability(
                    type='Sensitive Data Exposure',
                    severity=secret.severity,
                    endpoint=secret.source,
                    evidence=secret.value[:100]
                ))
        
        return vulns

# ==================== 主测试引擎 ====================

class DeepAPITesterV5:
    """深度 API 测试引擎 v5.0 - 最终版"""
    
    def __init__(self, target: str, headless: bool = True, max_depth: int = 3):
        self.target = target.rstrip('/')
        self.headless = headless
        self.max_depth = max_depth
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # 核心组件
        self.fallback = FallbackMechanism(target, self.session)
        self.scanner = VulnerabilityScanner(target, self.session)
        
        # 数据
        self.js_contents: Dict[str, str] = {}
        self.traffic: List[Dict] = []
        self.endpoints: List[APIEndpoint] = []
        self.secrets: List[SensitiveData] = []
        self.vulnerabilities: List[Vulnerability] = []
    
    def run_full_test(self, output_file: str = 'v5_final_report.md'):
        """执行完整测试"""
        print(f"\n{'='*70}")
        print(f"深度 API 渗透测试 v5.0 (最终版)")
        print(f"目标：{self.target}")
        print(f"{'='*70}\n")
        
        # 1. 浏览器爬取
        self._crawl_with_browser()
        
        # 2. 提取 API (多策略 + Fallback)
        print(f"\n{'='*70}")
        print(f"[+] 提取 API 端点 (多策略)")
        print(f"{'='*70}\n")
        
        self.endpoints = self.fallback.extract_endpoints(self.js_contents, self.traffic)
        
        # 3. 漏洞扫描
        print(f"\n{'='*70}")
        print(f"[+] 漏洞扫描")
        print(f"{'='*70}\n")
        
        self.vulnerabilities = self.scanner.scan(self.endpoints, self.js_contents, self.secrets)
        
        # 4. 生成报告
        self._generate_report(output_file)
        
        print(f"\n{'='*70}")
        print(f"测试完成！")
        print(f"JS 文件：{len(self.js_contents)}")
        print(f"API 端点：{len(self.endpoints)}")
        print(f"敏感信息：{len(self.secrets)}")
        print(f"漏洞数量：{len(self.vulnerabilities)}")
        print(f"{'='*70}\n")
    
    def _crawl_with_browser(self):
        """浏览器爬取"""
        print(f"{'='*70}")
        print(f"[+] 使用无头浏览器爬取")
        print(f"{'='*70}\n")
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context(viewport={'width': 1920, 'height': 1080})
            page = context.new_page()
            
            def handle_request(request):
                self.traffic.append({
                    'url': request.url,
                    'method': request.method,
                    'resource_type': request.resource_type
                })
                
                if request.resource_type == 'script':
                    self.js_contents[request.url] = ''
                    print(f"  [JS] {request.url[:100]}...")
            
            page.on('request', handle_request)
            
            try:
                page.goto(self.target, wait_until='networkidle', timeout=30000)
                page.wait_for_timeout(5000)
                self._interact_with_page(page)
            except Exception as e:
                print(f"[!] 错误：{e}")
            finally:
                browser.close()
    
    def _interact_with_page(self, page):
        """页面交互"""
        # 点击按钮
        buttons = page.query_selector_all('button, a, input[type="button"]')
        for btn in buttons[:20]:
            try:
                btn.click()
                page.wait_for_timeout(500)
            except:
                pass
        
        # 滚动
        page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
        page.wait_for_timeout(1000)
        page.evaluate('window.scrollTo(0, 0)')
    
    def _generate_report(self, output_file: str):
        """生成报告"""
        report = f"""# 深度 API 渗透测试报告 v5.0 (最终版)

## 执行摘要
- **测试目标**: {self.target}
- **测试时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}
- **测试工具**: Deep API Tester v5.0

## 发现统计
| 类型 | 数量 |
|------|------|
| JS 文件 | {len(self.js_contents)} |
| API 端点 | {len(self.endpoints)} |
| 敏感信息 | {len(self.secrets)} |
| 漏洞数量 | {len(self.vulnerabilities)} |

## JS 文件
"""
        for js in self.js_contents.keys():
            report += f"- `{js}`\n"
        
        report += f"\n## API 端点\n"
        for ep in self.endpoints[:30]:
            report += f"- `{ep.method} {ep.url}` ({ep.discovered_by})\n"
        
        if self.secrets:
            report += f"\n## 敏感信息\n"
            for secret in self.secrets:
                report += f"- **[{secret.severity}]** {secret.type}: `{secret.value[:50]}...`\n"
        
        if self.vulnerabilities:
            report += f"\n## 漏洞详情\n"
            for vuln in self.vulnerabilities:
                report += f"### {vuln.type}\n"
                report += f"- **严重程度**: {vuln.severity}\n"
                report += f"- **端点**: {vuln.endpoint}\n"
                report += f"- **证据**: {vuln.evidence[:200]}\n\n"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"\n[+] 报告已保存：{output_file}")


# CLI 入口
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python deep_api_tester_v5.py <target_url> [output_file]")
        sys.exit(1)
    
    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else 'v5_final_report.md'
    
    tester = DeepAPITesterV5(target)
    tester.run_full_test(output)
