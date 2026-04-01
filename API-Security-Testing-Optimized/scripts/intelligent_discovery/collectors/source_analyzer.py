"""
Intelligent API Discovery - Source Analyzer

全资源分析器，负责：
1. 使用 LLM 分析 JS/CSS/HTML 内容
2. 提取 API 端点、模式、技术栈信息

注意：这是工具而非推理者，具体分析策略由 Agent Brain 决定
"""

import json
import re
from typing import List, Dict, Optional, Any, Set
from urllib.parse import urljoin, urlparse

from ..models import (
    Endpoint, Pattern, Insight, AnalysisResult,
    Observation, ObservationType, TechStack, TechStackType, Finding, InsightType
)


LLM_ANALYSIS_PROMPT = """分析以下 {source_type} 代码，找出所有 API 调用和端点。

不只是找字符串字面量，还要理解：
1. 动态构建的 URL（如 baseURL + path）
2. 环境变量或配置中的 API 地址
3. 通过函数调用间接访问的 API
4. 条件分支中的不同 API
5. WebSocket 连接
6. GraphQL 查询
7. RESTful 路由模式

代码片段：
{code}

输出 JSON 格式：
{{
  "endpoints": [
    {{
      "path": "/api/users",
      "method": "GET",
      "construction": "literal|dynamic|indirect",
      "confidence": 0.0-1.0,
      "reasoning": "如何发现这个端点"
    }}
  ],
  "api_bases": ["http://api.example.com"],
  "patterns": ["/api/{{resource}}/{{id}}"],
  "websocket_urls": ["wss://..."],
  "tech_hints": ["Vue.js", "Axios"],
  "errors": []
}}"""


class SourceAnalyzer:
    """
    源代码分析器
    
    提供源代码分析能力，由 Agent Brain 决定分析什么
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self._found_paths: Set[str] = set()
    
    def analyze_js(
        self,
        content: str,
        context: 'DiscoveryContext',
        source_url: str = ""
    ) -> AnalysisResult:
        """
        分析 JavaScript 代码
        
        Args:
            content: JS 文件内容
            context: 发现上下文
            source_url: JS 文件 URL
            
        Returns:
            AnalysisResult: 分析结果
        """
        result = AnalysisResult()
        
        if self.llm_client and len(content) > 100:
            result = self._analyze_with_llm(content, "JavaScript", source_url)
        else:
            result = self._analyze_heuristic(content, "javascript")
        
        return result
    
    def analyze_html(
        self,
        content: str,
        context: 'DiscoveryContext',
        base_url: str = ""
    ) -> AnalysisResult:
        """
        分析 HTML 内容
        
        Args:
            content: HTML 内容
            context: 发现上下文
            base_url: 页面基础 URL
            
        Returns:
            AnalysisResult: 分析结果
        """
        result = AnalysisResult()
        
        result = self._analyze_html_heuristic(content, base_url)
        
        return result
    
    def analyze_css(
        self,
        content: str,
        context: 'DiscoveryContext'
    ) -> AnalysisResult:
        """
        分析 CSS 内容
        
        Args:
            content: CSS 内容
            context: 发现上下文
            
        Returns:
            AnalysisResult: 分析结果
        """
        result = AnalysisResult()
        
        url_patterns = [
            r'url\s*\(\s*["\']?([^"\')\s]+)',
            r'@import\s+["\']([^"\']+)',
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if 'api' in match.lower() or any(
                    keyword in match.lower()
                    for keyword in ['/rest/', '/graphql', '/v1/', '/v2/']
                ):
                    result.endpoints.append(Endpoint(
                        path=match,
                        method="GET",
                        source="css_analysis",
                        confidence=0.3
                    ))
        
        return result
    
    def analyze_response(
        self,
        content: str,
        context: 'DiscoveryContext',
        endpoint: str = ""
    ) -> AnalysisResult:
        """
        分析 API 响应内容
        
        Args:
            content: 响应内容
            context: 发现上下文
            endpoint: 请求的端点
            
        Returns:
            AnalysisResult: 分析结果
        """
        result = AnalysisResult()
        
        try:
            if content.strip().startswith('{') or content.strip().startswith('['):
                data = json.loads(content)
                
                result.endpoints.extend(self._infer_from_response_data(data, endpoint))
                
                result.insights.extend(self._generate_response_insights(data, endpoint))
            
            elif '<?xml' in content[:10]:
                result = self._analyze_xml_response(content, endpoint)
            
            elif 'swagger' in content.lower() or 'openapi' in content.lower():
                result = self._parse_openapi_spec(content)
        
        except json.JSONDecodeError:
            pass
        
        return result
    
    def _analyze_with_llm(
        self,
        code: str,
        source_type: str,
        source_url: str = ""
    ) -> AnalysisResult:
        """使用 LLM 分析代码"""
        result = AnalysisResult()
        
        prompt = LLM_ANALYSIS_PROMPT.format(
            source_type=source_type,
            code=code[:5000]
        )
        
        try:
            response = self.llm_client.generate(prompt)
            data = json.loads(response)
            
            for ep_data in data.get("endpoints", []):
                path = ep_data.get("path", "")
                if path and path not in self._found_paths:
                    self._found_paths.add(path)
                    result.endpoints.append(Endpoint(
                        path=path,
                        method=ep_data.get("method", "GET"),
                        source="llm_analysis",
                        confidence=ep_data.get("confidence", 0.7)
                    ))
            
            for pattern in data.get("patterns", []):
                result.patterns.append(Pattern(
                    template=pattern,
                    example=pattern,
                    confidence=0.6
                ))
            
            for api_base in data.get("api_bases", []):
                if not getattr(self, '_api_base', None):
                    self._api_base = api_base
            
            result.tech_stack_hints.extend(data.get("tech_hints", []))
            
        except (json.JSONDecodeError, Exception) as e:
            result.errors.append(f"LLM analysis failed: {str(e)}")
            result = self._analyze_heuristic(code, source_type.lower())
        
        return result
    
    def _analyze_heuristic(
        self,
        content: str,
        source_type: str
    ) -> AnalysisResult:
        """启发式分析（无 LLM 时的回退方案）"""
        result = AnalysisResult()
        
        api_patterns = [
            (r'["\']\/api\/[a-zA-Z0-9_\/\-\.]+["\']', 'GET'),
            (r'["\']\/v\d+\/[a-zA-Z0-9_\/\-\.]+["\']', 'GET'),
            (r'["\']\/rest\/[a-zA-Z0-9_\/\-\.]+["\']', 'GET'),
            (r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']', None),
            (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'GET'),
            (r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\'](/[^"\']+)["\']', None),
            (r'baseURL\s*[=:]\s*["\']([^"\']+)["\']', 'GET'),
            (r'API_URL\s*[=:]\s*["\']([^"\']+)["\']', 'GET'),
            (r'apiUrl\s*[=:]\s*["\']([^"\']+)["\']', 'GET'),
        ]
        
        found_paths: Set[str] = set()
        
        for pattern, default_method in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    method = match[0].upper() if match[0].lower() in ['get', 'post', 'put', 'delete'] else (default_method or 'GET')
                    path = match[1] if len(match) > 1 else match[0]
                else:
                    method = default_method or 'GET'
                    path = match
                
                path = path.strip()
                if path and len(path) > 1 and path not in found_paths:
                    if not any(ext in path.lower() for ext in ['.css', '.jpg', '.png', '.svg', '.woff']):
                        found_paths.add(path)
                        result.endpoints.append(Endpoint(
                            path=path,
                            method=method,
                            source=f"{source_type}_regex",
                            confidence=0.6
                        ))
        
        ws_patterns = [
            r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
            r'wss?://[^\s"\'<>]+',
        ]
        
        for pattern in ws_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                result.endpoints.append(Endpoint(
                    path=match,
                    method="WS",
                    source=f"{source_type}_websocket",
                    confidence=0.7
                ))
        
        tech_hints = []
        if 'react' in content.lower():
            tech_hints.append("React")
        if 'vue' in content.lower():
            tech_hints.append("Vue.js")
        if 'angular' in content.lower():
            tech_hints.append("Angular")
        if 'axios' in content.lower():
            tech_hints.append("Axios")
        if 'jquery' in content.lower():
            tech_hints.append("jQuery")
        
        result.tech_stack_hints.extend(tech_hints)
        
        return result
    
    def _analyze_html_heuristic(
        self,
        content: str,
        base_url: str
    ) -> AnalysisResult:
        """启发式 HTML 分析"""
        result = AnalysisResult()
        
        script_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
        scripts = re.findall(script_pattern, content, re.IGNORECASE)
        
        link_pattern = r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']'
        styles = re.findall(link_pattern, content, re.IGNORECASE)
        
        api_links = re.findall(
            r'href=["\']([^"\']*(?:/api/|/rest/|/v\d+/)[^"\']*)["\']',
            content,
            re.IGNORECASE
        )
        
        for link in api_links:
            result.endpoints.append(Endpoint(
                path=link,
                method="GET",
                source="html_link",
                confidence=0.5
            ))
        
        forms = re.findall(
            r'<form[^>]+action=["\']([^"\']*)["\'][^>]*>',
            content,
            re.IGNORECASE
        )
        
        for form_action in forms:
            if form_action and '/api/' in form_action.lower():
                result.endpoints.append(Endpoint(
                    path=form_action,
                    method="POST",
                    source="html_form",
                    confidence=0.6
                ))
        
        result.tech_stack_hints.extend(self._detect_frontend_framework(content))
        
        return result
    
    def _detect_frontend_framework(self, html: str) -> List[str]:
        """检测前端框架"""
        hints = []
        html_lower = html.lower()
        
        if 'react' in html_lower or 'reactdom' in html_lower:
            hints.append("React")
        if 'vue' in html_lower or 'vuejs' in html_lower:
            hints.append("Vue.js")
        if 'angular' in html_lower:
            hints.append("Angular")
        if ' backbone' in html_lower:
            hints.append("Backbone.js")
        if 'jquery' in html_lower:
            hints.append("jQuery")
        if '__next' in html_lower:
            hints.append("Next.js")
        if 'nuxt' in html_lower:
            hints.append("Nuxt.js")
        
        return hints
    
    def _infer_from_response_data(
        self,
        data: Any,
        endpoint: str
    ) -> List[Endpoint]:
        """从响应数据推导端点"""
        endpoints = []
        
        if isinstance(data, dict):
            if 'data' in data and isinstance(data['data'], list):
                endpoints.extend(self._infer_crud_endpoints(endpoint))
            
            if 'pagination' in data or 'page' in data:
                endpoints.extend(self._infer_pagination_endpoints(endpoint, data))
            
            for key, value in data.items():
                if isinstance(value, dict):
                    nested_endpoint = self._build_nested_endpoint(endpoint, key)
                    if nested_endpoint:
                        endpoints.append(nested_endpoint)
        
        return endpoints
    
    def _infer_crud_endpoints(self, base_endpoint: str) -> List[Endpoint]:
        """推导 CRUD 端点"""
        endpoints = []
        
        if not base_endpoint:
            return endpoints
        
        base_path = base_endpoint.strip('/')
        parts = base_path.split('/')
        
        if len(parts) >= 2:
            resource = parts[-1]
            parent_path = '/'.join(parts[:-1])
            
            endpoints.extend([
                Endpoint(
                    path=f"/{parent_path}/{resource}",
                    method="POST",
                    source="crud_inference",
                    confidence=0.5
                ),
                Endpoint(
                    path=f"/{parent_path}/{resource}/{{id}}",
                    method="PUT",
                    source="crud_inference",
                    confidence=0.5
                ),
                Endpoint(
                    path=f"/{parent_path}/{resource}/{{id}}",
                    method="DELETE",
                    source="crud_inference",
                    confidence=0.5
                ),
            ])
        
        return endpoints
    
    def _infer_pagination_endpoints(
        self,
        base_endpoint: str,
        data: Dict
    ) -> List[Endpoint]:
        """推导分页端点"""
        endpoints = []
        
        if not base_endpoint:
            return endpoints
        
        page = data.get('page', 1)
        total_pages = data.get('total_pages', data.get('total', 10))
        
        for p in range(page + 1, min(page + 5, (total_pages or 10) + 1)):
            endpoints.append(Endpoint(
                path=base_endpoint if '?' in base_endpoint else f"{base_endpoint}?page={p}",
                method="GET",
                source="pagination_inference",
                confidence=0.6
            ))
        
        return endpoints
    
    def _build_nested_endpoint(
        self,
        base: str,
        key: str
    ) -> Optional[Endpoint]:
        """构建嵌套资源端点"""
        if not base or not key:
            return None
        
        if key in ['id', 'created_at', 'updated_at', 'status']:
            return None
        
        base_clean = base.strip('/')
        parts = base_clean.split('/')
        
        if len(parts) >= 2:
            parent_id = parts[-1]
            parent_resource = parts[-2]
            
            return Endpoint(
                path=f"/{''.join(parts[:-1])}/{key}",
                method="GET",
                source="nested_inference",
                confidence=0.4
            )
        
        return Endpoint(
            path=f"/api/{key}",
            method="GET",
            source="nested_inference",
            confidence=0.3
        )
    
    def _generate_response_insights(
        self,
        data: Any,
        endpoint: str
    ) -> List[Insight]:
        """生成响应洞察"""
        insights = []
        
        if isinstance(data, dict):
            if 'error' in data:
                insights.append(Insight(
                    type=InsightType.PATTERN,
                    content=f"错误响应包含信息: {data.get('error')}",
                    confidence=0.5,
                    findings=[
                        Finding(
                            what="发现错误字段",
                            so_what="可能暴露内部路径信息",
                            evidence=[str(data.get('error'))]
                        )
                    ]
                ))
            
            if '_links' in data or 'links' in data:
                insights.append(Insight(
                    type=InsightType.OPPORTUNITY,
                    content="发现 HATEOAS 链接",
                    confidence=0.8,
                    findings=[
                        Finding(
                            what="响应包含超媒体链接",
                            so_what="可以利用链接发现更多端点",
                            evidence=[str(data.get('_links', data.get('links')))]
                        )
                    ]
                ))
        
        return insights
    
    def _analyze_xml_response(
        self,
        content: str,
        endpoint: str
    ) -> AnalysisResult:
        """分析 XML 响应"""
        result = AnalysisResult()
        
        endpoint_patterns = re.findall(r'/[a-zA-Z0-9_/\-]+', content)
        for path in set(endpoint_patterns):
            if len(path) > 2 and '/api/' in path.lower():
                result.endpoints.append(Endpoint(
                    path=path,
                    method="GET",
                    source="xml_analysis",
                    confidence=0.5
                ))
        
        return result
    
    def _parse_openapi_spec(self, content: str) -> AnalysisResult:
        """解析 OpenAPI 规范"""
        result = AnalysisResult()
        
        try:
            spec = json.loads(content)
            
            servers = spec.get('servers', [])
            base_url = servers[0].get('url', '') if servers else ''
            
            paths = spec.get('paths', {})
            for path, methods in paths.items():
                for method in methods:
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        result.endpoints.append(Endpoint(
                            path=path,
                            method=method.upper(),
                            source="openapi_spec",
                            confidence=1.0
                        ))
            
            result.insights.append(Insight(
                type=InsightType.ENDPOINT,
                content=f"从 OpenAPI 规范中发现 {len(result.endpoints)} 个端点",
                confidence=1.0,
                findings=[
                    Finding(
                        what="OpenAPI 规范完整",
                        so_what="可以直接获取所有 API 端点",
                        evidence=[f"Base: {base_url}"]
                    )
                ]
            ))
        
        except json.JSONDecodeError:
            result.errors.append("Failed to parse OpenAPI spec")
        
        return result
    
    def reset(self):
        """重置分析器状态"""
        self._found_paths.clear()


def create_source_analyzer(llm_client=None) -> SourceAnalyzer:
    """创建源代码分析器"""
    return SourceAnalyzer(llm_client=llm_client)
