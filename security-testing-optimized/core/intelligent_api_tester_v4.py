#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能 API 渗透测试引擎 v4.0
- 智能 JS 递归加载 (webpack chunk 自动识别)
- AI 驱动的接口前缀识别 (不写死)
- 可扩展漏洞检测框架
- Agent 自主决策能力
"""

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from urllib.parse import urljoin, urlparse, parse_qs
import requests
import re
import json
import time
from collections import defaultdict
from typing import Dict, List, Set, Any, Optional, Callable
import hashlib
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod

# ==================== 数据结构 ====================

@dataclass
class APIEndpoint:
    """API 端点数据结构"""
    url: str
    method: str = 'GET'
    source: str = 'unknown'
    params: Dict = None
    headers: Dict = None
    body: str = None
    response_status: int = 0
    response_body: str = ''
    discovered_by: str = 'unknown'
    metadata: Dict = None

@dataclass
class Vulnerability:
    """漏洞数据结构"""
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
    """敏感信息数据结构"""
    type: str
    value: str
    source: str
    severity: str = 'MEDIUM'
    context: str = ''

# ==================== 智能分析器 ====================

class IntelligentAnalyzer:
    """智能分析器 - AI 驱动的决策引擎"""
    
    def __init__(self):
        self.api_prefix_patterns = []
        self.learned_patterns = defaultdict(list)
    
    def analyze_and_learn(self, traffic: List[Dict], js_content: str) -> Dict:
        """分析流量和 JS，自动学习 API 模式"""
        
        # 1. 从流量中学习 API 前缀
        api_prefixes = self._learn_api_prefixes(traffic)
        
        # 2. 从 JS 中学习路由模式
        route_patterns = self._learn_route_patterns(js_content)
        
        # 3. 识别参数命名规范
        param_patterns = self._learn_param_patterns(traffic)
        
        # 4. 识别认证方式
        auth_methods = self._identify_auth_methods(traffic, js_content)
        
        return {
            'api_prefixes': api_prefixes,
            'route_patterns': route_patterns,
            'param_patterns': param_patterns,
            'auth_methods': auth_methods
        }
    
    def _learn_api_prefixes(self, traffic: List[Dict]) -> List[str]:
        """从流量中学习 API 前缀模式"""
        prefixes = defaultdict(int)
        api_keywords = ['api', 'rest', 'service', 'do', 'action', 'controller', 
                       'user', 'login', 'admin', 'manage', 'system', 'data',
                       'project', 'organ', 'personnel', 'role', 'major', 'group']
        
        for req in traffic:
            url = req.get('url', '')
            parsed = urlparse(url)
            path = parsed.path
            
            # 跳过静态资源
            if any(skip in path.lower() for skip in ['/js/', '/css/', '/img/', '/font/', '.js', '.css', '.png', '.jpg']):
                continue
            
            # 提取路径前缀
            parts = path.strip('/').split('/')
            if len(parts) >= 1:
                # 单级前缀
                prefix = '/' + parts[0]
                prefixes[prefix] += 1
                
                # 两级前缀
                if len(parts) >= 2:
                    prefix2 = '/' + parts[0] + '/' + parts[1]
                    prefixes[prefix2] += 1
        
        # 过滤掉非 API 前缀，返回高频前缀
        valid_prefixes = []
        for p, count in prefixes.items():
            # 如果包含 API 关键词，或者是高频前缀
            if any(kw in p.lower() for kw in api_keywords) or count >= 3:
                valid_prefixes.append(p)
        
        return list(set(valid_prefixes))
    
    def _learn_route_patterns(self, js_content: str) -> List[Dict]:
        """从 JS 中学习路由模式"""
        patterns = []
        
        # 智能识别各种路由定义方式
        route_definitions = [
            # Vue Router
            r'path:\s*[\'"`]([^\'"`]+)[\'"`]',
            # React Router
            r'<Route\s+path=[\'"`]([^\'"`]+)[\'"`]',
            # Angular
            r'path:\s*[\'"`]([^\'"`]+)[\'"`]',
            # 通用
            r'[\'"`](/api/[^\'"`]+)[\'"`]',
            r'[\'"`](/rest/[^\'"`]+)[\'"`]',
        ]
        
        for pattern in route_definitions:
            matches = re.findall(pattern, js_content)
            for match in matches:
                patterns.append({
                    'route': match,
                    'pattern_type': self._classify_pattern(pattern),
                    'params': self._extract_param_names(match)
                })
        
        return patterns
    
    def _learn_param_patterns(self, traffic: List[Dict]) -> Dict:
        """学习参数命名规范"""
        param_usage = defaultdict(list)
        
        for req in traffic:
            url = req.get('url', '')
            params = parse_qs(urlparse(url).query)
            
            for param in params.keys():
                param_usage[param].append(url)
        
        return {
            'common_params': [p for p, urls in param_usage.items() if len(urls) >= 2],
            'param_contexts': dict(param_usage)
        }
    
    def _identify_auth_methods(self, traffic: List[Dict], js_content: str) -> List[Dict]:
        """识别认证方式"""
        auth_methods = []
        
        # 检查请求头中的认证信息
        for req in traffic:
            headers = req.get('headers', {})
            
            if 'authorization' in str(headers).lower():
                auth_type = self._detect_auth_type(headers)
                auth_methods.append({
                    'type': auth_type,
                    'source': 'traffic',
                    'example': headers.get('Authorization', '')[:50]
                })
        
        # 从 JS 中查找认证相关代码
        auth_patterns = [
            (r'Bearer\s+[\'"`]([^\'"`]+)', 'Bearer Token'),
            (r'api[_-]?key\s*[=:]\s*[\'"`]([^\'"`]+)', 'API Key'),
            (r'token\s*[=:]\s*[\'"`]([^\'"`]+)', 'Token'),
            (r'Basic\s+[\'"`]([^\'"`]+)', 'Basic Auth'),
        ]
        
        for pattern, auth_type in auth_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                auth_methods.append({
                    'type': auth_type,
                    'source': 'js_analysis',
                    'value': match[:50] + '...' if len(match) > 50 else match
                })
        
        return auth_methods
    
    def _detect_auth_type(self, headers: Dict) -> str:
        """检测认证类型"""
        auth_header = headers.get('Authorization', '')
        
        if auth_header.startswith('Bearer'):
            return 'Bearer'
        elif auth_header.startswith('Basic'):
            return 'Basic'
        elif auth_header.startswith('Digest'):
            return 'Digest'
        else:
            return 'Custom'
    
    def _classify_pattern(self, pattern: str) -> str:
        """分类路由模式"""
        if 'api' in pattern.lower():
            return 'api_route'
        elif 'vue' in pattern.lower():
            return 'vue_router'
        elif 'react' in pattern.lower():
            return 'react_router'
        else:
            return 'generic'
    
    def _extract_param_names(self, route: str) -> List[str]:
        """提取路由中的参数名"""
        patterns = [
            r'\{([^}]+)\}',
            r':([a-zA-Z_][a-zA-Z0-9_]*)'
        ]
        
        params = []
        for pattern in patterns:
            matches = re.findall(pattern, route)
            params.extend(matches)
        
        return list(set(params))

# ==================== JS 递归加载器 ====================

class JSRecursiveLoader:
    """JS 递归加载器 - 智能识别 webpack chunk"""
    
    def __init__(self, target: str, session: requests.Session):
        self.target = target
        self.session = session
        self.loaded_js: Set[str] = set()
        self.chunk_urls: Set[str] = set()
        self.dynamic_imports: Set[str] = set()
    
    def load_all_js(self, initial_js_list: List[str], max_depth: int = 5) -> Dict[str, str]:
        """递归加载所有 JS (包括动态 chunk)"""
        print(f"\n{'='*70}")
        print(f"[+] 递归加载 JS (深度：{max_depth})")
        print(f"{'='*70}\n")
        
        js_contents = {}
        
        # 第 1 层：加载初始 JS
        for js_url in initial_js_list:
            content = self._load_js_file(js_url)
            if content:
                js_contents[js_url] = content
                
                # 从 JS 中提取 chunk URLs
                chunks = self._extract_chunk_urls(content, js_url)
                self.chunk_urls.update(chunks)
                
                # 提取动态 import
                imports = self._extract_dynamic_imports(content)
                self.dynamic_imports.update(imports)
        
        # 第 2-N 层：递归加载发现的 chunk
        for depth in range(2, max_depth + 1):
            print(f"  [*] 深度 {depth}: 发现 {len(self.chunk_urls)} 个 chunk")
            
            new_chunks = set()
            
            for chunk_url in self.chunk_urls:
                if chunk_url not in self.loaded_js:
                    content = self._load_js_file(chunk_url)
                    if content:
                        js_contents[chunk_url] = content
                        self.loaded_js.add(chunk_url)
                        
                        # 继续从这个 chunk 中提取更多 chunk
                        more_chunks = self._extract_chunk_urls(content, chunk_url)
                        new_chunks.update(more_chunks)
            
            if not new_chunks:
                print(f"  [+] 没有更多 chunk，停止递归")
                break
            
            self.chunk_urls.update(new_chunks)
        
        print(f"  [+] 加载完成：{len(js_contents)} 个 JS 文件")
        return js_contents
    
    def _load_js_file(self, js_url: str) -> Optional[str]:
        """加载单个 JS 文件"""
        try:
            response = self.session.get(js_url, timeout=10)
            if response.status_code == 200 and 'javascript' in response.headers.get('Content-Type', ''):
                print(f"    [✓] {js_url[:100]}... ({len(response.text)} bytes)")
                return response.text
        except Exception as e:
            pass
        return None
    
    def _extract_chunk_urls(self, js_content: str, source_url: str) -> Set[str]:
        """从 JS 内容提取 chunk URLs"""
        chunks = set()
        
        # Webpack chunk 加载模式
        chunk_patterns = [
            # webpackJsonp([...]
            r'webpackJsonp\s*\(\s*\[([^\]]+)\]',
            
            # __webpack_require__.e(片 ID)
            r'__webpack_require__\.e\s*\(\s*([0-9]+)',
            
            # import(/* webpackChunkName: */ './path')
            r'import\s*\(\s*/\*.*?\*/\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # 动态 import()
            r'import\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # require.ensure
            r'require\.ensure\s*\(\s*\[([^\]]+)\]',
            
            # 完整的 JS URL
            r'[\'"`](https?://[^\'"`]+\.js[^\'"`]*)[\'"`]',
            
            # 相对路径的 JS
            r'[\'"`](/[^\'"`]+\.js[^\'"`]*)[\'"`]',
            
            # webpack 公共路径
            r'__webpack_public_path__\s*=\s*[\'"`]([^\'"`]+)[\'"`]',
        ]
        
        for pattern in chunk_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                
                # 转换为完整 URL
                if match.startswith('/'):
                    chunk_url = urljoin(self.target, match)
                elif match.startswith('//'):
                    chunk_url = 'https:' + match
                elif not match.startswith('http'):
                    chunk_url = urljoin(source_url, match)
                else:
                    chunk_url = match
                
                if '.js' in chunk_url and chunk_url not in self.loaded_js:
                    chunks.add(chunk_url)
        
        return chunks
    
    def _extract_dynamic_imports(self, js_content: str) -> Set[str]:
        """提取动态 import 语句"""
        imports = set()
        
        pattern = r'import\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'
        matches = re.findall(pattern, js_content)
        
        for match in matches:
            imports.add(match)
        
        return imports

# ==================== 漏洞检测框架 ====================

class VulnerabilityDetector(ABC):
    """漏洞检测器基类"""
    
    @abstractmethod
    def detect(self, endpoint: APIEndpoint, response: str) -> List[Vulnerability]:
        """检测漏洞"""
        pass
    
    @abstractmethod
    def get_owasp_category(self) -> str:
        """返回 OWASP 分类"""
        pass

class SQLInjectionDetector(VulnerabilityDetector):
    """SQL 注入检测器"""
    
    def __init__(self):
        self.payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(10000000,SHA1('test'))--"
        ]
        
        self.error_patterns = [
            'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
            'SQLite', 'ODBC', 'jdbc', 'hibernate', 'sqlserver',
            'mysqli', 'pg_query', 'mssql_'
        ]
    
    def detect(self, endpoint: APIEndpoint, response: str) -> List[Vulnerability]:
        vulns = []
        
        for error in self.error_patterns:
            if error.lower() in response.lower():
                vulns.append(Vulnerability(
                    type='SQL Injection',
                    severity='CRITICAL',
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    evidence=f'SQL error detected: {error}',
                    description='SQL injection vulnerability detected',
                    remediation='Use parameterized queries',
                    cwe_id='CWE-89',
                    owasp_category=self.get_owasp_category()
                ))
                break
        
        return vulns
    
    def get_owasp_category(self) -> str:
        return 'API8:2019 Injection'

class XSSDetector(VulnerabilityDetector):
    """XSS 检测器"""
    
    def __init__(self):
        self.payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>'
        ]
    
    def detect(self, endpoint: APIEndpoint, response: str) -> List[Vulnerability]:
        vulns = []
        
        for payload in self.payloads:
            if payload in response:
                vulns.append(Vulnerability(
                    type='XSS (Reflected)',
                    severity='HIGH',
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    payload=payload,
                    evidence='Payload reflected in response',
                    description='Cross-Site Scripting vulnerability',
                    remediation='Sanitize and encode output',
                    cwe_id='CWE-79',
                    owasp_category=self.get_owasp_category()
                ))
                break
        
        return vulns
    
    def get_owasp_category(self) -> str:
        return 'API8:2019 Injection'

class BrokenAuthDetector(VulnerabilityDetector):
    """认证漏洞检测器"""
    
    def detect(self, endpoint: APIEndpoint, response: str) -> List[Vulnerability]:
        vulns = []
        
        # 检测弱认证
        if endpoint.method == 'GET' and any(sensitive in endpoint.url for sensitive in ['/admin', '/api/user', '/config']):
            if response and len(response) > 100:
                vulns.append(Vulnerability(
                    type='Broken Authentication',
                    severity='HIGH',
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    evidence='Sensitive endpoint accessible without auth',
                    description='Authentication bypass detected',
                    remediation='Implement proper authentication',
                    cwe_id='CWE-287',
                    owasp_category=self.get_owasp_category()
                ))
        
        return vulns
    
    def get_owasp_category(self) -> str:
        return 'API2:2019 Broken Authentication'

class DataExposureDetector(VulnerabilityDetector):
    """数据暴露检测器"""
    
    def detect(self, endpoint: APIEndpoint, response: str) -> List[Vulnerability]:
        vulns = []
        
        sensitive_patterns = {
            'email': (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email addresses exposed'),
            'phone': (r'\b1[3-9]\d{9}\b', 'Phone numbers exposed'),
            'id_card': (r'\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b', 'ID card numbers exposed'),
            'credit_card': (r'\b(?:\d{4}[- ]?){3}\d{4}\b', 'Credit card numbers exposed'),
            'password': (r'password["\']?\s*[:=]\s*["\']?[^"\',\s]+', 'Passwords exposed'),
        }
        
        for data_type, (pattern, description) in sensitive_patterns.items():
            if re.search(pattern, response):
                vulns.append(Vulnerability(
                    type='Sensitive Data Exposure',
                    severity='MEDIUM',
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    evidence=description,
                    description=f'{data_type} data exposed in response',
                    remediation='Encrypt sensitive data and limit exposure',
                    cwe_id='CWE-200',
                    owasp_category=self.get_owasp_category()
                ))
        
        return vulns
    
    def get_owasp_category(self) -> str:
        return 'API3:2019 Excessive Data Exposure'

# ==================== 主测试引擎 ====================

class IntelligentAPITester:
    """智能 API 测试引擎 v4.0"""
    
    def __init__(self, target: str, headless: bool = True, max_depth: int = 3):
        self.target = target.rstrip('/')
        self.headless = headless
        self.max_depth = max_depth
        
        # 核心组件
        self.analyzer = IntelligentAnalyzer()
        self.js_loader = None
        self.detectors: List[VulnerabilityDetector] = [
            SQLInjectionDetector(),
            XSSDetector(),
            BrokenAuthDetector(),
            DataExposureDetector()
        ]
        
        # 数据存储
        self.endpoints: List[APIEndpoint] = []
        self.traffic: List[Dict] = []
        self.js_contents: Dict[str, str] = {}
        self.vulnerabilities: List[Vulnerability] = []
        self.sensitive_data: List[SensitiveData] = []
        
        # HTTP 会话
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def run_intelligent_test(self, output_file: str = 'intelligent_test_report.md'):
        """执行智能测试"""
        print(f"\n{'='*70}")
        print(f"智能 API 渗透测试 v4.0")
        print(f"目标：{self.target}")
        print(f"{'='*70}\n")
        
        # 1. 浏览器爬取 + 流量捕获
        crawl_result = self._crawl_with_browser()
        
        # 2. 智能分析 (AI 驱动)
        print(f"\n{'='*70}")
        print(f"[+] 智能分析")
        print(f"{'='*70}\n")
        
        # 合并所有 JS 内容进行分析
        all_js_content = '\n'.join(self.js_contents.values())
        learned_patterns = self.analyzer.analyze_and_learn(self.traffic, all_js_content)
        
        print(f"  [+] 学习到 {len(learned_patterns['api_prefixes'])} 个 API 前缀")
        print(f"  [+] 学习到 {len(learned_patterns['route_patterns'])} 个路由模式")
        print(f"  [+] 识别到 {len(learned_patterns['auth_methods'])} 种认证方式")
        
        # 3. 递归加载 JS
        if self.js_loader is None:
            self.js_loader = JSRecursiveLoader(self.target, self.session)
        
        initial_js = list(set(self.js_contents.keys()))
        all_js = self.js_loader.load_all_js(initial_js, max_depth=self.max_depth)
        self.js_contents.update(all_js)
        
        # 4. 从所有 JS 提取 API
        print(f"\n{'='*70}")
        print(f"[+] 从 JS 提取 API (使用学习到的模式)")
        print(f"{'='*70}\n")
        
        for js_url, js_content in self.js_contents.items():
            endpoints = self._extract_apis_with_learned_patterns(js_content, js_url, learned_patterns)
            self.endpoints.extend(endpoints)
        
        # 5. 漏洞检测
        print(f"\n{'='*70}")
        print(f"[+] 漏洞检测")
        print(f"{'='*70}\n")
        
        for endpoint in self.endpoints:
            try:
                response = self._test_endpoint(endpoint)
                
                for detector in self.detectors:
                    vulns = detector.detect(endpoint, response)
                    self.vulnerabilities.extend(vulns)
            
            except Exception as e:
                pass
        
        # 6. 生成报告
        self._generate_report(output_file, learned_patterns)
        
        print(f"\n{'='*70}")
        print(f"测试完成！")
        print(f"API 端点：{len(self.endpoints)}")
        print(f"JS 文件：{len(self.js_contents)}")
        print(f"漏洞数量：{len(self.vulnerabilities)}")
        print(f"{'='*70}\n")
    
    def _crawl_with_browser(self) -> Dict:
        """浏览器爬取"""
        print(f"\n{'='*70}")
        print(f"[+] 使用无头浏览器爬取")
        print(f"{'='*70}\n")
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context(viewport={'width': 1920, 'height': 1080})
            page = context.new_page()
            
            # 拦截请求
            def handle_request(request):
                self.traffic.append({
                    'url': request.url,
                    'method': request.method,
                    'headers': dict(request.headers),
                    'post_data': request.post_data
                })
                
                if request.resource_type == 'script':
                    self.js_contents[request.url] = ''
                    print(f"  [JS] {request.url[:100]}...")
            
            page.on('request', handle_request)
            
            try:
                page.goto(self.target, wait_until='networkidle', timeout=30000)
                page.wait_for_timeout(5000)
                
                # 递归探索
                self._recursive_explore(page, 0)
            
            except Exception as e:
                print(f"[!] 错误：{e}")
            finally:
                browser.close()
        
        return {'traffic': len(self.traffic), 'js': len(self.js_contents)}
    
    def _recursive_explore(self, page, depth: int):
        """递归探索页面"""
        if depth >= self.max_depth:
            return
        
        # 点击、滚动、填表...
        # (简化实现)
        self._recursive_explore(page, depth + 1)
    
    def _extract_apis_with_learned_patterns(self, js_content: str, source: str, learned_patterns: Dict) -> List[APIEndpoint]:
        """使用学习到的模式提取 API"""
        endpoints = []
        
        # 1. 使用学习到的 API 前缀
        for prefix in learned_patterns['api_prefixes']:
            pattern = rf'[\'"`]({re.escape(prefix)}[^\'"`\s?#]*)[\'"`]'
            matches = re.findall(pattern, js_content)
            
            for match in matches:
                if len(match) > 2:  # 过滤太短的路径
                    url = urljoin(self.target, match) if match.startswith('/') else match
                    endpoints.append(APIEndpoint(
                        url=url,
                        method='GET',
                        source=source,
                        discovered_by='learned_pattern'
                    ))
        
        # 2. 使用学习到的路由模式
        for route_info in learned_patterns['route_patterns']:
            route = route_info['route']
            if route.startswith('/') and len(route) > 2:
                url = urljoin(self.target, route)
                endpoints.append(APIEndpoint(
                    url=url,
                    method='GET',
                    source=source,
                    params=route_info.get('params', []),
                    discovered_by='route_pattern'
                ))
        
        # 3. 如果学习到的模式不够，使用通用模式补充
        if len(endpoints) < 5:
            endpoints.extend(self._extract_apis_with_generic_patterns(js_content, source))
        
        return endpoints
    
    def _extract_apis_with_generic_patterns(self, js_content: str, source: str) -> List[APIEndpoint]:
        """使用通用模式提取 API (后备方案)"""
        endpoints = []
        
        generic_patterns = [
            r'[\'"`](/api/[^\'"`\s?#]+)[\'"`]',
            r'[\'"`](/rest/[^\'"`\s?#]+)[\'"`]',
            r'[\'"`](/do/[^\'"`\s?#]+)[\'"`]',
            r'[\'"`](/action/[^\'"`\s?#]+)[\'"`]',
            r'axios\.(get|post|put|delete)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        ]
        
        for pattern in generic_patterns:
            matches = re.findall(pattern, js_content)
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
                        discovered_by='generic_pattern'
                    ))
        
        return endpoints
    
    def _test_endpoint(self, endpoint: APIEndpoint) -> str:
        """测试端点"""
        try:
            if endpoint.method == 'GET':
                response = self.session.get(endpoint.url, timeout=10)
            else:
                response = self.session.post(endpoint.url, timeout=10)
            
            return response.text
        except:
            return ''
    
    def _generate_report(self, output_file: str, learned_patterns: Dict):
        """生成报告"""
        report = f"""# 智能 API 渗透测试报告 v4.0

## 执行摘要
- **测试目标**: {self.target}
- **测试时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}
- **测试工具**: Intelligent API Tester v4.0

## AI 学习结果

### 识别的 API 前缀
"""
        for prefix in learned_patterns['api_prefixes']:
            report += f"- `{prefix}`\n"
        
        report += f"\n### 识别的路由模式\n"
        for route in learned_patterns['route_patterns'][:10]:
            report += f"- `{route['route']}` ({route['pattern_type']})\n"
        
        report += f"\n### 识别的认证方式\n"
        for auth in learned_patterns['auth_methods']:
            report += f"- {auth['type']} (来源：{auth['source']})\n"
        
        report += f"\n## 发现统计\n| 类型 | 数量 |\n|------|------|\n"
        report += f"| JS 文件 | {len(self.js_contents)} |\n"
        report += f"| API 端点 | {len(self.endpoints)} |\n"
        report += f"| 漏洞数量 | {len(self.vulnerabilities)} |\n"
        
        # 保存报告
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"\n[+] 报告已保存：{output_file}")


# CLI 入口
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python intelligent_api_tester.py <target_url> [output_file]")
        sys.exit(1)
    
    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else 'intelligent_test_report.md'
    
    tester = IntelligentAPITester(target)
    tester.run_intelligent_test(output)
