# 深度 API 渗透测试引擎 v3.0

## 核心问题

### 当前 v2.0 的缺陷

1. ❌ **硬编码路径** - 使用固定列表扫描
2. ❌ **无 JS 分析** - 不从 JS 提取接口
3. ❌ **无浏览器** - 不执行 JS 发现动态路由
4. ❌ **无流量拦截** - 不分析 XHR/Fetch 请求
5. ❌ **无智能分析** - 简单匹配响应状态码

### 真正的深入测试应该

1. ✅ **无头浏览器** - Playwright 执行 JS
2. ✅ **流量拦截** - 捕获所有 API 请求
3. ✅ **JS 分析** - 正则提取 API 端点
4. ✅ **智能决策** - 根据响应内容判断
5. ✅ **有章法** - 按 OWASP API Top 10 系统测试

---

## v3.0 架构设计

```
深度测试引擎/
├── browser_crawler.py          # 无头浏览器爬虫
│   - 使用 Playwright
│   - 拦截所有网络请求
│   - 执行 JS 发现动态路由
│
├── js_analyzer.py              # JS 分析器
│   - 提取 JS 中的 API 端点
│   - 分析路由配置
│   - 发现硬编码密钥
│
├── api_mapper.py               # API 映射器
│   - 整合浏览器和 JS 分析结果
│   - 生成完整 API 地图
│   - 识别参数和请求方法
│
├── vulnerability_scanner.py    # 漏洞扫描器
│   - 按 OWASP API Top 10 测试
│   - 智能 payload 选择
│   - 基于响应内容分析
│
└── report_generator.py         # 报告生成器
    - 详细漏洞证明
    - 修复建议
    - 风险评级
```

---

## 核心代码实现

### 1. 无头浏览器爬虫

```python
# browser_crawler.py
from playwright.sync_api import sync_playwright
from urllib.parse import urlparse
import re

class BrowserCrawler:
    def __init__(self, target):
        self.target = target
        self.api_endpoints = []
        self.requests_log = []
        
    def crawl(self):
        """使用无头浏览器爬取网站，拦截所有 API 请求"""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            
            # 拦截所有请求
            page.on('request', self._handle_request)
            page.on('response', self._handle_response)
            
            # 访问目标
            page.goto(self.target, wait_until='networkidle')
            
            # 执行 JS 发现更多路由
            self._discover_routes(page)
            
            # 点击所有链接
            self._click_all_links(page)
            
            browser.close()
            
        return {
            'endpoints': self.api_endpoints,
            'requests': self.requests_log
        }
    
    def _handle_request(self, request):
        """拦截请求"""
        url = request.url
        method = request.method
        headers = request.headers
        post_data = request.post_data
        
        # 只记录 API 请求
        if self._is_api_request(url):
            self.requests_log.append({
                'url': url,
                'method': method,
                'headers': headers,
                'post_data': post_data
            })
    
    def _handle_response(self, response):
        """拦截响应"""
        url = response.url
        if self._is_api_request(url):
            self.api_endpoints.append({
                'url': url,
                'method': response.request.method,
                'status': response.status,
                'content_type': response.headers.get('content-type')
            })
    
    def _is_api_request(self, url):
        """判断是否是 API 请求"""
        api_patterns = [
            r'/api/',
            r'/api/v\d+/',
            r'/rest/',
            r'/graphql',
            r'/service/',
            r'\.json$',
            r'\.action$',
            r'/do/'
        ]
        return any(re.search(pattern, url) for pattern in api_patterns)
    
    def _discover_routes(self, page):
        """执行 JS 发现路由"""
        js_code = """
        () => {
            const routes = [];
            
            // 从 Vue Router 获取路由
            if (window.$route && window.$router) {
                window.$router.options.routes.forEach(route => {
                    routes.push(route.path);
                });
            }
            
            // 从 React Router 获取路由
            const reactRouter = document.querySelector('[data-reactroot]');
            if (reactRouter) {
                // React 路由提取逻辑
            }
            
            // 从所有 script 标签提取
            document.querySelectorAll('script').forEach(script => {
                if (script.src) {
                    routes.push(script.src);
                }
            });
            
            return routes;
        }
        """
        
        routes = page.evaluate(js_code)
        for route in routes:
            if isinstance(route, str) and route.startswith('/'):
                self.api_endpoints.append({
                    'url': self.target.rstrip('/') + route,
                    'source': 'vue_router'
                })
    
    def _click_all_links(self, page):
        """点击所有链接发现更多接口"""
        links = page.query_selector_all('a')
        for link in links:
            try:
                link.click()
                page.wait_for_load_state('networkidle')
            except:
                pass
```

---

### 2. JS 分析器

```python
# js_analyzer.py
import re
import requests
from urllib.parse import urljoin

class JSAnalyzer:
    def __init__(self, target):
        self.target = target
        self.api_endpoints = []
        self.secrets = []
        
    def analyze_all_js(self):
        """分析所有 JS 文件"""
        js_files = self._find_all_js_files()
        
        for js_file in js_files:
            self._analyze_js_file(js_file)
        
        return {
            'endpoints': self.api_endpoints,
            'secrets': self.secrets
        }
    
    def _find_all_js_files(self):
        """找到所有 JS 文件"""
        response = requests.get(self.target)
        html = response.text
        
        # 提取所有 script src
        js_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
        js_files = re.findall(js_pattern, html)
        
        # 转换为绝对 URL
        return [urljoin(self.target, js) for js in js_files]
    
    def _analyze_js_file(self, js_url):
        """分析单个 JS 文件"""
        try:
            response = requests.get(js_url)
            js_content = response.text
            
            # 提取 API 端点
            self._extract_api_endpoints(js_content, js_url)
            
            # 提取敏感信息
            self._extract_secrets(js_content, js_url)
            
        except Exception as e:
            print(f"[!] Failed to analyze {js_url}: {e}")
    
    def _extract_api_endpoints(self, content, source):
        """从 JS 内容提取 API 端点"""
        patterns = [
            # axios.get('/api/...')
            r'axios\.(get|post|put|delete)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # fetch('/api/...')
            r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # @/api/...
            r'[\'"`](@/api/[^\'"`]+)[\'"`]',
            
            # process.env.VUE_APP_BASE_API
            r'process\.env\.VUE_APP_[A-Z_]+',
            
            # http://... 或 https://...
            r'(https?://[^\'"`\s]+/api/[^\'"`\s]+)',
            
            # /api/v1/...
            r'[\'"`](/api/[^\'"`]+)[\'"`]',
            
            # router.push('/...')
            r'router\.push\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # this.\$axios...
            r'this\.\$axios\.(get|post|put|delete)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                endpoint = match[1] if isinstance(match, tuple) else match
                
                # 清理端点
                endpoint = endpoint.replace('${', '{').replace('}', '')
                
                if endpoint.startswith('/') or endpoint.startswith('http'):
                    self.api_endpoints.append({
                        'url': endpoint,
                        'source': source,
                        'pattern': pattern
                    })
    
    def _extract_secrets(self, content, source):
        """提取敏感信息"""
        secret_patterns = [
            # API Key
            r'(?:api[_-]?key|apikey)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # Token
            r'(?:token|auth[_-]?token)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # Password
            r'(?:password|passwd|pwd)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # Secret
            r'(?:secret|secret[_-]?key)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # AWS
            r'(?:AKIA|ABIA|ACCA)[A-Z0-9]{16}',
            
            # 数据库连接字符串
            r'(?:mongodb|mysql|postgresql|redis)://[^\s\'"`]+'
        ]
        
        for pattern in secret_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self.secrets.append({
                    'type': 'sensitive_data',
                    'value': match,
                    'source': source
                })
```

---

### 3. API 映射器

```python
# api_mapper.py
from collections import defaultdict

class APIMapper:
    def __init__(self):
        self.api_map = defaultdict(dict)
        
    def build_map(self, browser_results, js_results):
        """整合浏览器和 JS 分析结果，构建完整 API 地图"""
        
        # 从浏览器结果添加
        for endpoint in browser_results.get('endpoints', []):
            self._add_endpoint(endpoint)
        
        # 从 JS 结果添加
        for endpoint in js_results.get('endpoints', []):
            self._add_endpoint(endpoint)
        
        # 去重和整理
        return self._organize_map()
    
    def _add_endpoint(self, endpoint):
        """添加端点到地图"""
        url = endpoint['url']
        method = endpoint.get('method', 'GET')
        
        # 解析 URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path
        
        # 添加到地图
        if path not in self.api_map:
            self.api_map[path] = {
                'methods': set(),
                'parameters': [],
                'sources': []
            }
        
        self.api_map[path]['methods'].add(method)
        self.api_map[path]['sources'].append(endpoint.get('source', 'unknown'))
    
    def _organize_map(self):
        """整理 API 地图"""
        organized = []
        
        for path, info in self.api_map.items():
            organized.append({
                'path': path,
                'methods': list(info['methods']),
                'parameters': info['parameters'],
                'sources': list(set(info['sources']))
            })
        
        # 按路径排序
        organized.sort(key=lambda x: x['path'])
        
        return organized
```

---

### 4. 智能漏洞扫描器

```python
# vulnerability_scanner.py
import requests
from bs4 import BeautifulSoup

class VulnerabilityScanner:
    def __init__(self, api_map, target):
        self.api_map = api_map
        self.target = target
        self.session = requests.Session()
        self.vulnerabilities = []
        
    def scan_all(self):
        """扫描所有漏洞"""
        # OWASP API Top 10
        self.test_api1_broken_object_level_auth()
        self.test_api2_broken_user_auth()
        self.test_api3_excessive_data_exposure()
        self.test_api4_lack_of_resources_rate_limiting()
        self.test_api5_broken_function_level_auth()
        self.test_api6_mass_assignment()
        self.test_api7_security_misconfiguration()
        self.test_api8_injection()
        self.test_api9_improper_assets_management()
        self.test_api10_insufficient_logging_monitoring()
        
        return self.vulnerabilities
    
    def test_api8_injection(self):
        """测试注入漏洞 (API8:2019)"""
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "1; DROP TABLE users--",
            "' UNION SELECT NULL,NULL,NULL--"
        ]
        
        for endpoint in self.api_map:
            path = endpoint['path']
            
            for method in endpoint['methods']:
                for payload in sqli_payloads:
                    # 测试 URL 参数
                    test_url = f"{self.target}{path}"
                    params = {'id': payload, 'search': payload}
                    
                    response = self.session.get(test_url, params=params)
                    
                    # 智能分析响应
                    if self._detect_sqli(response):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'endpoint': path,
                            'method': method,
                            'payload': payload,
                            'evidence': self._get_evidence(response)
                        })
    
    def _detect_sqli(self, response):
        """智能检测 SQL 注入"""
        # 检测错误信息
        sqli_errors = [
            'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
            'SQLite', 'ODBC', 'jdbc', 'hibernate'
        ]
        
        # 检测响应异常
        if any(error in response.text for error in sqli_errors):
            return True
        
        # 检测响应时间异常（时间盲注）
        # 需要对比基线响应时间
        
        return False
    
    def _get_evidence(self, response):
        """获取漏洞证据"""
        # 提取相关行
        soup = BeautifulSoup(response.text, 'html.parser')
        error_div = soup.find('div', {'class': 'error'})
        if error_div:
            return error_div.text[:200]
        
        return response.text[:200]
```

---

## 使用示例

```python
# 完整测试流程
from browser_crawler import BrowserCrawler
from js_analyzer import JSAnalyzer
from api_mapper import APIMapper
from vulnerability_scanner import VulnerabilityScanner

target = "http://49.65.100.160:6004/"

# 1. 浏览器爬取
crawler = BrowserCrawler(target)
browser_results = crawler.crawl()

# 2. JS 分析
js_analyzer = JSAnalyzer(target)
js_results = js_analyzer.analyze_all_js()

# 3. 构建 API 地图
mapper = APIMapper()
api_map = mapper.build_map(browser_results, js_results)

# 4. 漏洞扫描
scanner = VulnerabilityScanner(api_map, target)
vulnerabilities = scanner.scan_all()

# 5. 生成报告
print(f"发现 {len(api_map)} 个 API 端点")
print(f"发现 {len(vulnerabilities)} 个漏洞")
```

---

## 依赖安装

```bash
pip install playwright requests beautifulsoup4
playwright install chromium
```

---

## 对比

| 功能 | v2.0 | v3.0 |
|------|------|------|
| 端点发现 | 硬编码列表 | 浏览器 + JS 分析 |
| 动态路由 | ❌ | ✅ |
| XHR 拦截 | ❌ | ✅ |
| 密钥提取 | ❌ | ✅ |
| 智能分析 | 状态码匹配 | 响应内容分析 |
| OWASP Top 10 | 部分 | 完整 |

---

*设计版本：v3.0*
*设计时间：2026-03-30*
