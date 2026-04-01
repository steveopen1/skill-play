"""
Intelligent API Discovery - Response Analyzer

响应推导引擎，负责：
1. 从 API 响应推导相关端点
2. 分析分页、嵌套资源、CRUD 模式
3. 解析 HATEOAS、Swagger/OpenAPI

注意：这是工具而非推理者，具体推导策略由 Agent Brain 决定
"""

import json
import re
from typing import List, Dict, Optional, Any, Set
from urllib.parse import urlparse, parse_qs

from ..models import (
    Endpoint, Pattern, Insight, InsightType, AnalysisResult, NetworkRequest,
    Observation, ObservationType, TechStack, TechStackType, Finding
)


class ResponseAnalyzer:
    """
    API 响应分析器
    
    从 API 响应推导更多端点
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
    
    def analyze(
        self,
        response: NetworkRequest,
        context: 'DiscoveryContext'
    ) -> AnalysisResult:
        """
        分析 API 响应
        
        Args:
            response: 网络请求对象
            context: 发现上下文
            
        Returns:
            AnalysisResult: 分析结果
        """
        result = AnalysisResult()
        
        if not response.response_body:
            return result
        
        content = response.response_body
        
        if content.strip().startswith('{') or content.strip().startswith('['):
            result = self._analyze_json_response(content, response, context)
        elif '<?xml' in content[:10] or '<rss' in content[:10]:
            result = self._analyze_xml_response(content, response, context)
        elif 'swagger' in content.lower() or 'openapi' in content.lower():
            result = self._parse_openapi_spec(content)
        elif 'graphql' in content.lower():
            result = self._analyze_graphql_response(content, response, context)
        
        return result
    
    def infer_endpoints(
        self,
        response: NetworkRequest,
        context: 'DiscoveryContext'
    ) -> List[Endpoint]:
        """
        从响应推导端点
        
        Args:
            response: 网络请求对象
            context: 发现上下文
            
        Returns:
            List[Endpoint]: 推导的端点列表
        """
        endpoints = []
        
        result = self.analyze(response, context)
        endpoints.extend(result.endpoints)
        
        endpoints.extend(self._infer_pagination_endpoints(response))
        endpoints.extend(self._infer_crud_endpoints(response))
        endpoints.extend(self._infer_hateoas_endpoints(response))
        
        return endpoints
    
    def _analyze_json_response(
        self,
        content: str,
        response: NetworkRequest,
        context: 'DiscoveryContext'
    ) -> AnalysisResult:
        """分析 JSON 响应"""
        result = AnalysisResult()
        
        try:
            data = json.loads(content)
            
            endpoints = []
            endpoints.extend(self._infer_pagination_endpoints(response))
            endpoints.extend(self._infer_crud_endpoints(response))
            endpoints.extend(self._infer_hateoas_endpoints(response))
            
            result.endpoints.extend(endpoints)
            
            result.insights.extend(self._generate_insights_from_data(data, response))
            
            if isinstance(data, dict):
                if 'data' in data and isinstance(data['data'], list):
                    result.insights.append(Insight(
                        type=InsightType.PATTERN,
                        content="发现标准 REST 响应格式 (data 数组)",
                        confidence=0.7,
                        findings=[Finding(
                            what="标准化的响应结构",
                            so_what="可能存在分页和 CRUD 端点",
                            evidence=["data 字段包含数组"]
                        )]
                    ))
                
                if '_links' in data or 'links' in data:
                    links = data.get('_links', data.get('links', {}))
                    if isinstance(links, dict):
                        result.insights.append(Insight(
                            type=InsightType.OPPORTUNITY,
                            content="发现 HATEOAS 链接模式",
                            confidence=0.8,
                            findings=[Finding(
                                what="超媒体控制",
                                so_what="可以利用 Link 头或 _links 发现更多端点",
                                evidence=[str(list(links.keys())[:5])]
                            )]
                        ))
        
        except json.JSONDecodeError:
            pass
        
        return result
    
    def _infer_pagination_endpoints(self, response: NetworkRequest) -> List[Endpoint]:
        """推导分页端点"""
        endpoints = []
        
        if not response.response_body:
            return endpoints
        
        try:
            data = json.loads(response.response_body)
            
            page = data.get('page', data.get('pageNum', data.get('current_page', 1)))
            total_pages = data.get('total_pages', data.get('total', data.get('total_pages', 10)))
            per_page = data.get('per_page', data.get('page_size', data.get('limit', 20)))
            
            if isinstance(total_pages, int) and total_pages > page:
                for p in range(page + 1, min(page + 6, total_pages + 1)):
                    new_url = self._add_or_replace_param(response.url, 'page', str(p))
                    endpoints.append(Endpoint(
                        path=urlparse(new_url).path,
                        method=response.method,
                        source="pagination_inference",
                        confidence=0.6
                    ))
            
            if 'next' in data or 'has_more' in data:
                if data.get('next') or data.get('has_more'):
                    endpoints.append(Endpoint(
                        path=urlparse(response.url).path,
                        method=response.method,
                        source="pagination_inference",
                        confidence=0.7
                    ))
        
        except (json.JSONDecodeError, ValueError):
            pass
        
        return endpoints
    
    def _infer_crud_endpoints(self, response: NetworkRequest) -> List[Endpoint]:
        """推导 CRUD 端点"""
        endpoints = []
        
        parsed = urlparse(response.url)
        path = parsed.path
        
        parts = path.strip('/').split('/')
        if len(parts) < 2:
            return endpoints
        
        resource = parts[-1]
        base_path = '/' + '/'.join(parts[:-1])
        
        singular_resource = self._to_singular(resource)
        
        crud_indicators = ['get', 'list', 'fetch', 'find']
        if response.method == 'GET' and any(ind in resource.lower() for ind in crud_indicators):
            endpoints.extend([
                Endpoint(
                    path=f"{base_path}",
                    method="POST",
                    source="crud_inference",
                    confidence=0.5
                ),
                Endpoint(
                    path=f"/{base_path.lstrip('/')}/{singular_resource}",
                    method="POST",
                    source="crud_inference",
                    confidence=0.5
                ),
            ])
        
        if response.method == 'GET' and not any(ind in resource.lower() for ind in crud_indicators):
            endpoints.extend([
                Endpoint(
                    path=f"{base_path}",
                    method="POST",
                    source="crud_inference",
                    confidence=0.5
                ),
                Endpoint(
                    path=f"/{base_path.lstrip('/')}/{singular_resource}",
                    method="PUT",
                    source="crud_inference",
                    confidence=0.5
                ),
                Endpoint(
                    path=f"/{base_path.lstrip('/')}/{singular_resource}",
                    method="DELETE",
                    source="crud_inference",
                    confidence=0.5
                ),
            ])
        
        return endpoints
    
    def _infer_hateoas_endpoints(self, response: NetworkRequest) -> List[Endpoint]:
        """从 HATEOAS 链接推导端点"""
        endpoints = []
        
        if not response.response_body:
            return endpoints
        
        try:
            data = json.loads(response.response_body)
            
            hateoas_links = []
            
            if isinstance(data, dict):
                if '_links' in data:
                    hateoas_links = data['_links']
                elif 'links' in data:
                    hateoas_links = data['links']
                elif 'href' in data:
                    hateoas_links = {'self': {'href': data['href']}}
            
            if isinstance(hateoas_links, dict):
                for rel, link_info in hateoas_links.items():
                    if isinstance(link_info, dict):
                        href = link_info.get('href', '')
                    elif isinstance(link_info, str):
                        href = link_info
                    else:
                        continue
                    
                    if href and not href.startswith('#'):
                        parsed = urlparse(href)
                        if parsed.scheme or parsed.netloc or parsed.path.startswith('/'):
                            endpoints.append(Endpoint(
                                path=parsed.path or '/',
                                method="GET",
                                source="hateoas_inference",
                                confidence=0.8
                            ))
            
            link_header = response.response_headers.get('link', '')
            if link_header:
                endpoints.extend(self._parse_link_header(link_header))
        
        except (json.JSONDecodeError, ValueError):
            pass
        
        return endpoints
    
    def _parse_link_header(self, link_header: str) -> List[Endpoint]:
        """解析 HTTP Link 头"""
        endpoints = []
        
        links = re.findall(r'<([^>]+)>;\s*rel="([^"]+)"', link_header)
        for url, rel in links:
            if rel in ['next', 'prev', 'related', 'alternate']:
                parsed = urlparse(url)
                endpoints.append(Endpoint(
                    path=parsed.path or '/',
                    method="GET",
                    source="link_header",
                    confidence=0.8
                ))
        
        return endpoints
    
    def _analyze_xml_response(
        self,
        content: str,
        response: NetworkRequest,
        context: 'DiscoveryContext'
    ) -> AnalysisResult:
        """分析 XML 响应"""
        result = AnalysisResult()
        
        href_patterns = re.findall(r'href=["\']([^"\']+)["\']', content)
        for href in href_patterns:
            if '/api/' in href.lower() or '/rest/' in href.lower():
                result.endpoints.append(Endpoint(
                    path=href,
                    method="GET",
                    source="xml_href",
                    confidence=0.6
                ))
        
        return result
    
    def _analyze_graphql_response(
        self,
        content: str,
        response: NetworkRequest,
        context: 'DiscoveryContext'
    ) -> AnalysisResult:
        """分析 GraphQL 响应"""
        result = AnalysisResult()
        
        result.endpoints.append(Endpoint(
            path=urlparse(response.url).path,
            method="POST",
            source="graphql_endpoint",
            confidence=0.9
        ))
        
        result.insights.append(Insight(
            type=InsightType.ENDPOINT,
            content="发现 GraphQL 端点",
            confidence=0.9,
            findings=[Finding(
                what="GraphQL API",
                so_what="需要使用 GraphQL 查询发现更多字段和端点",
                evidence=[f"Endpoint: {response.url}"]
            )]
        ))
        
        return result
    
    def _parse_openapi_spec(self, content: str) -> AnalysisResult:
        """解析 OpenAPI/Swagger 规范"""
        result = AnalysisResult()
        
        try:
            spec = json.loads(content)
            
            servers = spec.get('servers', spec.get('host', []))
            if isinstance(servers, list) and servers:
                base_url = servers[0].get('url', '')
            elif isinstance(servers, str):
                base_url = servers
            else:
                base_url = ''
            
            paths = spec.get('paths', {})
            for path, methods in paths.items():
                for method in methods:
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
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
                findings=[Finding(
                    what="完整的 API 规范",
                    so_what="可以直接获取所有端点定义",
                    evidence=[f"Base URL: {base_url}"]
                )]
            ))
        
        except (json.JSONDecodeError, ValueError):
            result.errors.append("Failed to parse OpenAPI spec")
        
        return result
    
    def _generate_insights_from_data(
        self,
        data: Any,
        response: NetworkRequest
    ) -> List[Insight]:
        """从数据生成洞察"""
        insights = []
        
        if isinstance(data, dict):
            if 'error' in data or 'message' in data:
                error_msg = data.get('error', data.get('message', ''))
                if isinstance(error_msg, str):
                    insights.append(Insight(
                        type=InsightType.PATTERN,
                        content=f"API 返回错误: {error_msg[:50]}",
                        confidence=0.4,
                        findings=[Finding(
                            what="错误响应",
                            so_what="可能包含内部路径或参数信息",
                            evidence=[error_msg[:100]]
                        )]
                    ))
            
            if 'metadata' in data or 'meta' in data:
                meta = data.get('metadata', data.get('meta', {}))
                if isinstance(meta, dict):
                    insights.append(Insight(
                        type=InsightType.PATTERN,
                        content="发现元数据字段",
                        confidence=0.5,
                        findings=[Finding(
                            what="响应包含元数据",
                            so_what="可能指示更多 API 端点",
                            evidence=[str(list(meta.keys())[:5])]
                        )]
                    ))
        
        return insights
    
    def _add_or_replace_param(self, url: str, param: str, value: str) -> str:
        """在 URL 中添加或替换参数"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [value]
        new_query = '&'.join(f"{k}={v[0]}" for k, v in query.items())
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def _to_singular(self, word: str) -> str:
        """复数转单数"""
        if word.endswith('ies'):
            return word[:-3] + 'y'
        elif word.endswith('es'):
            return word[:-2]
        elif word.endswith('s') and len(word) > 1:
            return word[:-1]
        return word


def create_response_analyzer(llm_client=None) -> ResponseAnalyzer:
    """创建响应分析器"""
    return ResponseAnalyzer(llm_client=llm_client)
