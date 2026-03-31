#!/usr/bin/env python3
"""
Collectors Coordinator - 采集器联动管理器

协调各种采集器的工作：
1. HTTP 采集器 - 基础 HTTP 请求采集
2. JS 采集器 - JavaScript 文件分析
3. Browser 采集器 - 无头浏览器动态采集

实现信息共享和协同工作。
"""

import time
from typing import Dict, List, Set, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging

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
    BROWSER = "browser"
    API_PATH = "api_path"


@dataclass
class CollectedData:
    """采集数据容器"""
    target: str
    
    js_urls: List[str] = field(default_factory=list)
    api_endpoints: List[Dict[str, str]] = field(default_factory=list)
    dynamic_urls: List[str] = field(default_factory=list)
    api_requests: List[Dict] = field(default_factory=list)
    
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
    采集器联动管理器
    
    协调各种采集器的工作流程：
    
    1. HTTP 采集 → 基础信息收集
       - 服务器信息
       - 响应头
       - Cookie
    
    2. Browser 采集 → 动态内容获取
       - JS 文件列表
       - AJAX 请求捕获
       - 表单信息
    
    3. JS 分析 → API 端点提取
       - 从 JS 中提取 API 路径
       - 提取配置信息
       - 发现内网地址
    """
    
    def __init__(self, target: str, session: 'requests.Session' = None):
        self.target = target.rstrip('/')
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.data = CollectedData(target=target)
        
        self._collectors_initialized = False
        self._http_collector = None
        self._js_collector = None
        self._browser_collector = None
    
    def _init_http_collector(self):
        """初始化 HTTP 采集器"""
        if not HAS_REQUESTS:
            logger.warning("requests 库不可用")
            return
        
        try:
            resp = self.session.get(self.target, timeout=10, allow_redirects=True)
            self.data.headers = dict(resp.headers)
            
            if 'Server' in resp.headers:
                self.data.insights.append(f"Web 服务器: {resp.headers['Server']}")
            
            for cookie in self.session.cookies:
                self.data.cookies[cookie.name] = cookie.value
                
            logger.info(f"HTTP 采集完成: {len(resp.headers)} headers")
        except Exception as e:
            self.data.errors.append(f"HTTP 采集失败: {str(e)}")
            logger.error(f"HTTP 采集失败: {e}")
    
    def _init_js_collector(self):
        """初始化 JS 采集器"""
        try:
            from .js_collector import JSCollector
            self._js_collector = JSCollector(
                session=self.session,
                max_depth=3,
                max_js_per_depth=50
            )
            logger.info("JS 采集器初始化完成")
        except ImportError as e:
            logger.warning(f"JS 采集器导入失败: {e}")
    
    def _init_browser_collector(self):
        """初始化 Browser 采集器"""
        try:
            from .browser_collector import HeadlessBrowserCollector
            self._browser_collector = HeadlessBrowserCollector(
                headless=True,
                timeout=30000
            )
            logger.info("Browser 采集器初始化完成")
        except ImportError as e:
            logger.warning(f"Browser 采集器导入失败: {e}")
            logger.warning("请安装: pip install playwright && playwright install chromium")
    
    def _collect_with_browser(self) -> bool:
        """
        使用无头浏览器采集
        
        Returns:
            是否成功
        """
        if not self._browser_collector:
            return False
        
        try:
            logger.info("[Browser] 开始采集...")
            
            # 1. 导航到目标
            self._browser_collector.navigate(self.target)
            time.sleep(2)
            
            # 2. 获取 JS URLs
            js_urls = self._browser_collector.get_dynamic_js_urls()
            if js_urls:
                self.data.js_urls.extend(js_urls)
                logger.info(f"[Browser] 发现 {len(js_urls)} 个 JS URLs")
            
            # 3. 获取 API 请求
            api_requests = self._browser_collector.get_api_requests()
            if api_requests:
                self.data.api_requests.extend(api_requests)
                logger.info(f"[Browser] 发现 {len(api_requests)} 个 API 请求")
            
            # 4. 获取 WebSocket 连接
            ws_connections = self._browser_collector.get_websocket_connections()
            if ws_connections:
                self.data.insights.append(f"发现 {len(ws_connections)} 个 WebSocket 连接")
            
            # 5. 尝试交互并采集更多请求
            self._browser_collector.click_and_intercept(['button', 'a'])
            time.sleep(1)
            
            api_requests = self._browser_collector.get_api_requests()
            if api_requests:
                self.data.api_requests.extend(api_requests)
            
            return True
            
        except Exception as e:
            self.data.errors.append(f"Browser 采集失败: {str(e)}")
            logger.error(f"Browser 采集失败: {e}")
            return False
    
    def _collect_js_analysis(self):
        """JS 文件分析"""
        if not self._js_collector:
            return
        
        try:
            logger.info("[JS] 开始分析...")
            
            # 如果没有 JS URLs，先获取 HTML 中的
            if not self.data.js_urls:
                resp = self.session.get(self.target, timeout=10)
                html = resp.text
                
                import re
                js_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
                matches = re.findall(js_pattern, html)
                for match in matches:
                    if match.startswith('http'):
                        self.data.js_urls.append(match)
                    else:
                        from urllib.parse import urljoin
                        self.data.js_urls.append(urljoin(self.target, match))
            
            # 分析每个 JS 文件
            for js_url in self.data.js_urls[:20]:
                try:
                    resp = self.session.get(js_url, timeout=10)
                    content = resp.text
                    
                    # 提取 API 端点
                    endpoints = self._extract_endpoints_from_js(content)
                    self.data.api_endpoints.extend(endpoints)
                    
                    # 提取后端 API 地址
                    api_base = self._extract_api_base_from_js(content)
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
            
            logger.info(f"[JS] 分析完成: {len(self.data.api_endpoints)} 个端点")
            
        except Exception as e:
            self.data.errors.append(f"JS 分析失败: {str(e)}")
            logger.error(f"JS 分析失败: {e}")
    
    def _extract_endpoints_from_js(self, content: str) -> List[Dict[str, str]]:
        """从 JS 内容中提取 API 端点"""
        endpoints = []
        found = set()
        
        import re
        
        patterns = [
            (r'["\']/api/[^"\']+["\']', 'GET'),
            (r'["\']/personnelWeb/[^"\']+["\']', 'GET'),
            (r'["\']/\w+/[^"\']+["\']', 'GET'),
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
                        'source': 'js_analysis'
                    })
        
        return endpoints
    
    def _extract_api_base_from_js(self, content: str) -> Optional[str]:
        """从 JS 内容中提取 API 基础地址"""
        import re
        
        patterns = [
            r'baseURL["\']?\s*[:=]\s*["\']([^"\']+)',
            r'apiUrl["\']?\s*[:=]\s*["\']([^"\']+)',
            r'serverUrl["\']?\s*[:=]\s*["\']([^"\']+)',
            r'apiBase["\']?\s*[:=]\s*["\']([^"\']+)',
            r'https?://[a-zA-Z0-9.-]+(:\d+)?/personnelWeb',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            if matches:
                return matches[0]
        
        return None
    
    def _extract_sensitive_urls(self, content: str) -> List[str]:
        """提取敏感 URL"""
        import re
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
        import re
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
    
    def _test_discovered_endpoints(self):
        """测试发现的端点"""
        if not self.data.backend_api_base:
            return
        
        base = self.data.backend_api_base.rstrip('/')
        
        # 规范化端点路径
        for ep in self.data.api_endpoints[:30]:
            path = ep['path']
            if not path.startswith('/'):
                path = '/' + path
            
            url = base + path
            
            try:
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                
                if resp.status_code != 404:
                    self.data.insights.append(
                        f"端点可达: {ep['method']} {path} -> {resp.status_code}"
                    )
                    
                    # 如果返回 HTML，可能是 API 代理
                    if 'text/html' in resp.headers.get('Content-Type', ''):
                        if 'api' not in path.lower():
                            self.data.insights.append(f"  可能不是 API 端点 (返回 HTML)")
                
            except Exception:
                pass
    
    def collect(self, use_browser: bool = True) -> CollectedData:
        """
        执行完整的采集流程
        
        Args:
            use_browser: 是否使用无头浏览器
        
        Returns:
            采集的数据
        """
        logger.info(f"[*] 开始采集: {self.target}")
        logger.info("=" * 60)
        
        start_time = time.time()
        
        # 1. HTTP 基础采集
        logger.info("[1/4] HTTP 基础采集...")
        self._init_http_collector()
        
        # 2. Browser 动态采集
        if use_browser:
            logger.info("[2/4] Browser 动态采集...")
            self._init_browser_collector()
            self._collect_with_browser()
        else:
            logger.info("[2/4] Browser 采集已跳过")
        
        # 3. JS 文件分析
        logger.info("[3/4] JS 文件分析...")
        self._init_js_collector()
        self._collect_js_analysis()
        
        # 4. 端点测试
        logger.info("[4/4] 端点测试...")
        self._test_discovered_endpoints()
        
        elapsed = time.time() - start_time
        
        # 统计
        self.data.collector_stats = {
            'http': {'success': len(self.data.headers) > 0},
            'browser': {'success': len(self.data.js_urls) > 0 or len(self.data.api_requests) > 0},
            'js': {'endpoints_found': len(self.data.api_endpoints)},
            'total_time': elapsed
        }
        
        logger.info("=" * 60)
        logger.info(f"[*] 采集完成 (耗时: {elapsed:.2f}s)")
        logger.info(f"    JS URLs: {len(self.data.js_urls)}")
        logger.info(f"    API 端点: {len(self.data.api_endpoints)}")
        logger.info(f"    API 请求: {len(self.data.api_requests)}")
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
    
    target = sys.argv[1]
    
    coordinator = create_coordinator(target)
    data = coordinator.collect(use_browser=True)
    
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
