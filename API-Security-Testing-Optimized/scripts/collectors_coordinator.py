#!/usr/bin/env python3
"""
Collectors Coordinator - 采集器联动管理器 v2.0

协调所有采集器的工作：
1. JSCollector - JavaScript 文件分析
2. ApiPathFinder - API 路径发现
3. URLCollector - URL 采集
4. HeadlessBrowserCollector - 无头浏览器动态采集
5. APIfuzzer - API 路径模糊测试

实现真正的信息共享和协同工作。
"""

import time
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import re

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger(__name__)


class CollectorType(Enum):
    """采集器类型"""
    HTTP = "http"
    JS = "js"
    API_PATH = "api_path"
    URL = "url"
    BROWSER = "browser"
    FUZZER = "fuzzer"


@dataclass
class CollectedData:
    """采集数据容器"""
    target: str
    
    js_urls: List[str] = field(default_factory=list)
    js_contents: Dict[str, str] = field(default_factory=dict)
    
    api_endpoints: List[Dict[str, str]] = field(default_factory=list)
    api_requests: List[Dict] = field(default_factory=list)
    
    url_endpoints: List[str] = field(default_factory=list)
    domains: Set[str] = field(default_factory=set)
    
    fuzz_targets: List[str] = field(default_factory=list)
    fuzz_results: List[Dict] = field(default_factory=list)
    
    sensitive_urls: List[str] = field(default_factory=list)
    internal_ips: List[str] = field(default_factory=list)
    backend_api_base: Optional[str] = None
    
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    
    insights: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    collector_stats: Dict[str, Dict] = field(default_factory=dict)


class CollectorsCoordinator:
    """
    采集器联动管理器 v2.0
    
    协调所有采集器的工作流程：
    
    ┌─────────────────────────────────────────────────────────────────┐
    │                    CollectorsCoordinator v2.0                         │
    ├─────────────────────────────────────────────────────────────────┤
    │                                                                   │
    │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐           │
    │  │  JSCollector │───▶│ ApiPathFinder│───▶│ APIfuzzer  │           │
    │  └─────────────┘    └─────────────┘    └─────────────┘           │
    │         │                                                 │           │
    │         ▼                                                 ▼           │
    │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐           │
    │  │URLCollector │    │  Browser    │    │ HTTP Probe │           │
    │  └─────────────┘    └─────────────┘    └─────────────┘           │
    │                                                                   │
    ├─────────────────────────────────────────────────────────────────┤
    │                      CollectedData (统一数据容器)                    │
    │   - js_urls / js_contents                                       │
    │   - api_endpoints / api_requests                                 │
    │   - fuzz_targets / fuzz_results                                 │
    │   - backend_api_base / internal_ips                             │
    └─────────────────────────────────────────────────────────────────┘
    """
    
    def __init__(self, target: str, session: 'requests.Session' = None):
        self.target = target.rstrip('/')
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.data = CollectedData(target=target)
        
        self._js_collector = None
        self._api_path_finder = None
        self._url_collector = None
        self._browser_collector = None
        self._fuzzer = None
    
    def _init_collectors(self):
        """初始化所有采集器"""
        # JS Collector
        try:
            from .collectors.js_collector import JSCollector
            self._js_collector = JSCollector(
                session=self.session,
                max_depth=3,
                max_js_per_depth=50
            )
            logger.info("JSCollector initialized")
        except (ImportError, ModuleNotFoundError) as e:
            try:
                from collectors.js_collector import JSCollector
                self._js_collector = JSCollector(
                    session=self.session,
                    max_depth=3,
                    max_js_per_depth=50
                )
                logger.info("JSCollector initialized")
            except ImportError as e2:
                logger.warning(f"JSCollector not available: {e2}")
        
        # API Path Finder
        try:
            from .collectors.api_path_finder import ApiPathFinder
            self._api_path_finder = ApiPathFinder()
            logger.info("ApiPathFinder initialized")
        except (ImportError, ModuleNotFoundError) as e:
            try:
                from collectors.api_path_finder import ApiPathFinder
                self._api_path_finder = ApiPathFinder()
                logger.info("ApiPathFinder initialized")
            except ImportError as e2:
                logger.warning(f"ApiPathFinder not available: {e2}")
        
        # URL Collector
        try:
            from .collectors.url_collector import URLCollector
            self._url_collector = URLCollector(session=self.session)
            logger.info("URLCollector initialized")
        except (ImportError, ModuleNotFoundError) as e:
            try:
                from collectors.url_collector import URLCollector
                self._url_collector = URLCollector(session=self.session)
                logger.info("URLCollector initialized")
            except ImportError as e2:
                logger.warning(f"URLCollector not available: {e2}")
        
        # Browser Collector
        try:
            from .collectors.browser_collector import HeadlessBrowserCollector
            self._browser_collector = HeadlessBrowserCollector(
                headless=True,
                timeout=30000
            )
            logger.info("HeadlessBrowserCollector initialized")
        except (ImportError, ModuleNotFoundError) as e:
            try:
                from collectors.browser_collector import HeadlessBrowserCollector
                self._browser_collector = HeadlessBrowserCollector(
                    headless=True,
                    timeout=30000
                )
                logger.info("HeadlessBrowserCollector initialized")
            except ImportError as e2:
                logger.warning(f"HeadlessBrowserCollector not available: {e2}")
        
        # Fuzzer
        try:
            from .api_fuzzer import APIfuzzer
            self._fuzzer = APIfuzzer(session=self.session)
            logger.info("APIfuzzer initialized")
        except (ImportError, ModuleNotFoundError) as e:
            try:
                from api_fuzzer import APIfuzzer
                self._fuzzer = APIfuzzer(session=self.session)
                logger.info("APIfuzzer initialized")
            except ImportError as e2:
                logger.warning(f"APIfuzzer not available: {e2}")
    
    def _http_basic_collection(self):
        """HTTP 基础采集"""
        logger.info("[HTTP] 基础信息采集...")
        
        try:
            resp = self.session.get(self.target, timeout=10, allow_redirects=True)
            self.data.headers = dict(resp.headers)
            self.data.cookies = {c.name: c.value for c in self.session.cookies}
            
            if 'Server' in resp.headers:
                self.data.insights.append(f"Web 服务器: {resp.headers['Server']}")
            
            logger.info(f"[HTTP] 获取到 {len(resp.headers)} 个响应头")
            
        except Exception as e:
            self.data.errors.append(f"HTTP 采集失败: {str(e)}")
            logger.error(f"HTTP 采集失败: {e}")
    
    def _collect_js_analysis(self) -> int:
        """
        JS 文件分析 + API 路径提取
        
        Returns:
            发现的端点数量
        """
        if not self._js_collector:
            return 0
        
        logger.info("[JS] 开始 JS 文件分析...")
        
        try:
            # 获取 HTML 中的 JS URLs
            resp = self.session.get(self.target, timeout=10)
            html = resp.text
            
            js_urls = self._js_collector.extract_js_from_html(html, self.target)
            self.data.js_urls.extend(js_urls)
            logger.info(f"[JS] 从 HTML 发现 {len(js_urls)} 个 JS 文件")
            
            # 分析每个 JS 文件
            for js_url in js_urls[:30]:
                try:
                    js_resp = self.session.get(js_url, timeout=10)
                    if js_resp.status_code == 200:
                        content = js_resp.text
                        self.data.js_contents[js_url] = content
                        
                        # ApiPathFinder 提取 API 路径
                        if self._api_path_finder:
                            apis = self._api_path_finder.find_api_paths_in_text(content, js_url)
                            for api in apis:
                                self.data.api_endpoints.append({
                                    'method': getattr(api, 'method', 'GET'),
                                    'path': getattr(api, 'path', ''),
                                    'source': 'js_api_finder'
                                })
                        
                        # 直接正则提取
                        endpoints = self._extract_endpoints_from_js(content)
                        self.data.api_endpoints.extend(endpoints)
                        
                        # 提取后端 API 地址
                        api_base = self._extract_api_base(content)
                        if api_base and not self.data.backend_api_base:
                            self.data.backend_api_base = api_base
                            self.data.insights.append(f"发现后端 API: {api_base}")
                        
                        # 提取敏感 URL
                        sensitive = self._extract_sensitive_urls(content)
                        self.data.sensitive_urls.extend(sensitive)
                        
                        # 提取内网 IP
                        ips = self._extract_internal_ips(content)
                        self.data.internal_ips.extend(ips)
                        
                except Exception as e:
                    logger.debug(f"JS 分析失败 {js_url}: {e}")
            
            # 去重
            self.data.api_endpoints = self._deduplicate_endpoints(self.data.api_endpoints)
            
            logger.info(f"[JS] 分析完成: {len(self.data.js_urls)} JS, {len(self.data.api_endpoints)} API 端点")
            
        except Exception as e:
            self.data.errors.append(f"JS 分析失败: {str(e)}")
            logger.error(f"JS 分析失败: {e}")
        
        return len(self.data.api_endpoints)
    
    def _collect_with_browser(self) -> int:
        """
        无头浏览器动态采集
        
        Returns:
            发现的请求数量
        """
        if not self._browser_collector:
            return 0
        
        logger.info("[Browser] 开始无头浏览器采集...")
        
        try:
            # 导航到目标
            self._browser_collector.navigate(self.target)
            time.sleep(2)
            
            # 获取动态 JS URLs
            dynamic_js = self._browser_collector.get_dynamic_js_urls()
            for js in dynamic_js:
                if js not in self.data.js_urls:
                    self.data.js_urls.append(js)
            
            # 获取 API 请求
            api_requests = self._browser_collector.get_api_requests()
            self.data.api_requests.extend(api_requests)
            
            # 尝试与页面交互
            self._browser_collector.click_and_intercept(['button', 'a', 'input'])
            time.sleep(1)
            
            # 再次获取请求
            more_requests = self._browser_collector.get_api_requests()
            self.data.api_requests.extend(more_requests)
            
            # 获取 WebSocket 连接
            ws = self._browser_collector.get_websocket_connections()
            if ws:
                self.data.insights.append(f"发现 {len(ws)} 个 WebSocket 连接")
            
            logger.info(f"[Browser] 采集完成: {len(dynamic_js)} JS, {len(self.data.api_requests)} 请求")
            
        except Exception as e:
            self.data.errors.append(f"Browser 采集失败: {str(e)}")
            logger.error(f"Browser 采集失败: {e}")
        
        return len(self.data.api_requests)
    
    def _collect_url_discovery(self) -> int:
        """
        URL 发现采集
        
        Returns:
            发现的 URL 数量
        """
        if not self._url_collector:
            return 0
        
        logger.info("[URL] 开始 URL 发现...")
        
        try:
            resp = self.session.get(self.target, timeout=10)
            html = resp.text
            
            # URL 采集
            url_result = self._url_collector.collect_from_html(html, self.target)
            
            self.data.domains.update(url_result.domains)
            self.data.url_endpoints.extend(url_result.static_urls)
            
            logger.info(f"[URL] 发现完成: {len(url_result.domains)} 域名, {len(url_result.static_urls)} URL")
            
        except Exception as e:
            self.data.errors.append(f"URL 采集失败: {str(e)}")
            logger.error(f"URL 采集失败: {e}")
        
        return len(self.data.url_endpoints)
    
    def _run_fuzzing(self, base_endpoints: List[Dict]) -> int:
        """
        API 路径模糊测试
        
        Args:
            base_endpoints: 基础端点列表
        
        Returns:
            发现的新目标数量
        """
        if not self._fuzzer:
            return 0
        
        logger.info("[Fuzzer] 开始 API 路径模糊测试...")
        
        try:
            # 从已有端点提取父路径
            parent_paths = set()
            for ep in base_endpoints:
                path = ep.get('path', '')
                parts = path.strip('/').split('/')
                if len(parts) > 1:
                    parent = '/' + '/'.join(parts[:-1])
                    parent_paths.add(parent)
            
            # 生成 Fuzz 目标
            fuzz_targets = []
            for parent in parent_paths:
                targets = self._fuzzer.generate_parent_fuzz_targets([parent], max_per_parent=10)
                fuzz_targets.extend(targets)
            
            # 测试 Fuzz 目标
            fuzz_results = []
            for target_path in fuzz_targets[:100]:
                url = self.target + target_path if not target_path.startswith('http') else target_path
                try:
                    resp = self.session.get(url, timeout=5, allow_redirects=False)
                    if resp.status_code < 500:
                        fuzz_results.append({
                            'path': target_path,
                            'status': resp.status_code,
                            'length': len(resp.content)
                        })
                        if resp.status_code != 404:
                            self.data.fuzz_targets.append(target_path)
                except:
                    pass
            
            self.data.fuzz_results = fuzz_results
            
            logger.info(f"[Fuzzer] 测试完成: {len(fuzz_targets)} 目标, {len(self.data.fuzz_targets)} 存活")
            
        except Exception as e:
            self.data.errors.append(f"Fuzzing 失败: {str(e)}")
            logger.error(f"Fuzzing 失败: {e}")
        
        return len(self.data.fuzz_targets)
    
    def _extract_endpoints_from_js(self, content: str) -> List[Dict[str, str]]:
        """从 JS 内容中提取 API 端点"""
        endpoints = []
        found = set()
        
        patterns = [
            (r'["\']/api/[^"\']+["\']', 'GET'),
            (r'["\']/personnelWeb/[^"\']+["\']', 'GET'),
            (r'["\']/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+["\']', 'GET'),
            (r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']', None),
            (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'GET'),
        ]
        
        for pattern, default_method in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    method = match[0].upper() if match[0].lower() in ['get', 'post', 'put', 'delete'] else (default_method or 'GET')
                    path = match[1] if len(match) > 1 else match[0]
                else:
                    method = default_method or 'GET'
                    path = match
                
                path = path.strip()
                if path and len(path) > 1 and path not in found:
                    found.add(path)
                    endpoints.append({
                        'method': method,
                        'path': path,
                        'source': 'js_regex'
                    })
        
        return endpoints
    
    def _extract_api_base(self, content: str) -> Optional[str]:
        """从 JS 内容中提取 API 基础地址"""
        patterns = [
            r'baseURL["\']?\s*[:=]\s*["\']([^"\']+)',
            r'apiUrl["\']?\s*[:=]\s*["\']([^"\']+)',
            r'serverUrl["\']?\s*[:=]\s*["\']([^"\']+)',
            r'apiBase["\']?\s*[:=]\s*["\']([^"\']+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            if matches:
                return matches[0]
        
        return None
    
    def _extract_sensitive_urls(self, content: str) -> List[str]:
        """提取敏感 URL"""
        urls = []
        patterns = [
            r'["\']/(?:admin|config|backup|db|sql|dump|phpinfo|env|git|\\.git)["\']',
            r'["\']/(?:api/v\d+/|rest/|graphql)[^"\']*["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            urls.extend(matches)
        
        return list(set(urls))
    
    def _extract_internal_ips(self, content: str) -> List[str]:
        """提取内网 IP"""
        ips = []
        patterns = [
            r'10\.\d+\.\d+\.\d+',
            r'192\.168\.\d+\.\d+',
            r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            ips.extend(matches)
        
        return list(set(ips))
    
    def _deduplicate_endpoints(self, endpoints: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """去重端点"""
        seen = set()
        unique = []
        
        for ep in endpoints:
            key = f"{ep.get('method', 'GET')}:{ep.get('path', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        
        return unique
    
    def collect(self, use_browser: bool = True, use_fuzzer: bool = True) -> CollectedData:
        """
        执行完整的采集流程
        
        Args:
            use_browser: 是否使用无头浏览器
            use_fuzzer: 是否使用模糊测试
        
        Returns:
            采集的数据
        """
        logger.info(f"[*] 开始采集: {self.target}")
        logger.info("=" * 60)
        
        start_time = time.time()
        
        # 初始化采集器
        self._init_collectors()
        
        # 1. HTTP 基础采集
        logger.info("[1/5] HTTP 基础采集...")
        self._http_basic_collection()
        
        # 2. JS 文件分析 + API 路径提取
        logger.info("[2/5] JS 文件分析...")
        js_count = self._collect_js_analysis()
        
        # 3. Browser 动态采集
        if use_browser:
            logger.info("[3/5] Browser 动态采集...")
            browser_count = self._collect_with_browser()
        else:
            logger.info("[3/5] Browser 采集已跳过")
        
        # 4. URL 发现
        logger.info("[4/5] URL 发现...")
        url_count = self._collect_url_discovery()
        
        # 5. Fuzzing
        if use_fuzzer and self.data.api_endpoints:
            logger.info("[5/5] API 路径模糊测试...")
            fuzz_count = self._run_fuzzing(self.data.api_endpoints)
        else:
            logger.info("[5/5] Fuzzing 已跳过")
        
        elapsed = time.time() - start_time
        
        # 统计
        self.data.collector_stats = {
            'http': {'success': len(self.data.headers) > 0},
            'js': {
                'js_files': len(self.data.js_urls),
                'endpoints': len(self.data.api_endpoints)
            },
            'browser': {'requests': len(self.data.api_requests)},
            'url': {'endpoints': len(self.data.url_endpoints)},
            'fuzzer': {
                'targets': len(self.data.fuzz_targets),
                'results': len(self.data.fuzz_results)
            },
            'total_time': elapsed
        }
        
        logger.info("=" * 60)
        logger.info(f"[*] 采集完成 (耗时: {elapsed:.2f}s)")
        logger.info(f"    JS 文件: {len(self.data.js_urls)}")
        logger.info(f"    API 端点: {len(self.data.api_endpoints)}")
        logger.info(f"    Browser 请求: {len(self.data.api_requests)}")
        logger.info(f"    URL 端点: {len(self.data.url_endpoints)}")
        logger.info(f"    Fuzz 目标: {len(self.data.fuzz_targets)}")
        logger.info(f"    后端 API: {self.data.backend_api_base or '未发现'}")
        
        return self.data
    
    def stop(self):
        """停止所有采集器"""
        if self._browser_collector:
            try:
                self._browser_collector.stop()
            except:
                pass
    
    def get_summary(self) -> Dict:
        """获取采集摘要"""
        return {
            'target': self.target,
            'backend_api_base': self.data.backend_api_base,
            'js_urls_count': len(self.data.js_urls),
            'api_endpoints_count': len(self.data.api_endpoints),
            'api_requests_count': len(self.data.api_requests),
            'url_endpoints_count': len(self.data.url_endpoints),
            'fuzz_targets_count': len(self.data.fuzz_targets),
            'internal_ips': list(set(self.data.internal_ips)),
            'insights': self.data.insights,
            'errors': self.data.errors
        }


def create_coordinator(target: str, session: 'requests.Session' = None) -> CollectorsCoordinator:
    """创建采集器联动管理器"""
    return CollectorsCoordinator(target, session)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python collectors_coordinator.py <target_url>")
        sys.exit(1)
    
    coordinator = create_coordinator(sys.argv[1])
    data = coordinator.collect(use_browser=True, use_fuzzer=True)
    
    print("\n" + "=" * 60)
    print("采集摘要")
    print("=" * 60)
    
    summary = coordinator.get_summary()
    for key, value in summary.items():
        if key not in ['insights', 'errors']:
            print(f"  {key}: {value}")
    
    if summary['insights']:
        print("\n洞察:")
        for insight in summary['insights']:
            print(f"  - {insight}")
    
    coordinator.stop()
