"""
Intelligent API Discovery - Insight Generator

洞察生成器，负责：
1. 从观察中生成洞察
2. 识别模式和机会
3. 为策略生成提供输入
"""

import json
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass

from .models import (
    Observation, Insight, InsightType, Finding,
    NetworkRequest, PageStructure, ActionType
)


LLM_INSIGHT_PROMPT = """分析以下观察结果，生成洞察。

观察类型：{obs_type}
观察来源：{obs_source}
内容摘要：{content_summary}

已发现 {endpoints_count} 个端点
技术栈：{tech_stack}
API Base：{api_base}

请生成洞察，识别：
1. 新发现的 API 端点或模式
2. 技术栈信息
3. 潜在的机会或障碍
4. 后续发现建议

输出 JSON 格式：
{{
  "insights": [
    {{
      "type": "endpoint|pattern|tech_stack|opportunity|blocker",
      "content": "洞察内容",
      "confidence": 0.0-1.0,
      "findings": [
        {{
          "what": "发现了什么",
          "so_what": "这意味着什么",
          "evidence": ["证据1", "证据2"]
        }}
      ]
    }}
  ]
}}"""


class InsightGenerator:
    """
    洞察生成器
    
    从观察中生成有价值的洞察
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
    
    def generate_from_observations(
        self,
        observations: List[Observation],
        context: 'DiscoveryContext'
    ) -> List[Insight]:
        """
        从观察列表生成洞察
        
        Args:
            observations: 观察列表
            context: 发现上下文
            
        Returns:
            List[Insight]: 生成的洞察列表
        """
        insights = []
        
        for obs in observations:
            if obs.type.value == "network_request":
                insight = self._analyze_network_request(obs, context)
                if insight:
                    insights.append(insight)
            
            elif obs.type.value == "page_structure":
                insight = self._analyze_page_structure(obs, context)
                if insight:
                    insights.append(insight)
            
            elif obs.type.value == "api_response":
                insight = self._analyze_api_response(obs, context)
                if insight:
                    insights.append(insight)
        
        insights.extend(self._identify_opportunities(context))
        
        return insights
    
    def _analyze_network_request(
        self,
        obs: Observation,
        context: 'DiscoveryContext'
    ) -> Optional[Insight]:
        """分析网络请求观察"""
        if not isinstance(obs.content, NetworkRequest):
            return None
        
        request: NetworkRequest = obs.content
        findings = []
        
        if request.is_api:
            findings.append(Finding(
                what=f"API 请求: {request.method} {request.url}",
                so_what="这是一个 API 端点",
                evidence=[f"响应状态: {request.response_status}"]
            ))
            
            if request.response_status == 401:
                findings.append(Finding(
                    what="认证要求",
                    so_what="该端点需要认证",
                    evidence=["401 Unauthorized"]
                ))
            
            elif request.response_status == 403:
                findings.append(Finding(
                    what="访问禁止",
                    so_what="可能被 WAF 拦截",
                    evidence=["403 Forbidden"]
                ))
        
        else:
            if '/api/' in request.url or '/v1/' in request.url:
                findings.append(Finding(
                    what=f"可能的 API URL: {request.url}",
                    so_what="可能包含隐藏的 API 端点",
                    evidence=["URL 模式匹配"]
                ))
        
        if findings:
            return Insight(
                type=InsightType.ENDPOINT if request.is_api else InsightType.PATTERN,
                content=f"从网络请求中发现 {'API' if request.is_api else '潜在端点'}",
                confidence=0.9 if request.is_api else 0.5,
                findings=findings
            )
        
        return None
    
    def _analyze_page_structure(
        self,
        obs: Observation,
        context: 'DiscoveryContext'
    ) -> Optional[Insight]:
        """分析页面结构观察"""
        if not isinstance(obs.content, PageStructure):
            return None
        
        page: PageStructure = obs.content
        findings = []
        
        if page.forms:
            findings.append(Finding(
                what=f"发现 {len(page.forms)} 个表单",
                so_what="表单提交可能触发 API 调用",
                evidence=[f"字段: {[f.get('fields', []) for f in page.forms[:2]]}"]
            ))
        
        if page.interactive_elements:
            findings.append(Finding(
                what=f"发现 {len(page.interactive_elements)} 个可交互元素",
                so_what="点击或输入可能触发 API",
                evidence=[f"类型: {set(e.get('type', '') for e in page.interactive_elements[:5])}"]
            ))
        
        if page.scripts:
            findings.append(Finding(
                what=f"页面包含 {len(page.scripts)} 个 JS 文件",
                so_what="需要分析 JS 获取 API 端点",
                evidence=[f"示例: {page.scripts[:2]}"]
            ))
        
        if findings:
            return Insight(
                type=InsightType.PATTERN,
                content=f"页面 {page.url} 包含可利用的交互点",
                confidence=0.7,
                findings=findings
            )
        
        return None
    
    def _analyze_api_response(
        self,
        obs: Observation,
        context: 'DiscoveryContext'
    ) -> Optional[Insight]:
        """分析 API 响应观察"""
        if not isinstance(obs.content, NetworkRequest):
            return None
        
        response: NetworkRequest = obs.content
        findings = []
        
        if not response.response_body:
            return None
        
        try:
            if response.response_body.strip().startswith('{'):
                data = json.loads(response.response_body)
                
                if 'data' in data and isinstance(data['data'], list):
                    findings.append(Finding(
                        what="列表响应结构",
                        so_what="可能存在分页和更多列表端点",
                        evidence=[f"数据条数: {len(data.get('data', []))}"]
                    ))
                
                if 'pagination' in data or 'page' in data:
                    findings.append(Finding(
                        what="分页信息",
                        so_what="可以尝试其他分页参数",
                        evidence=[str({k: v for k, v in data.items() if k in ['page', 'total', 'limit']})]
                    ))
                
                if '_links' in data or 'links' in data:
                    findings.append(Finding(
                        what="HATEOAS 链接",
                        so_what="可以利用链接发现更多端点",
                        evidence=[str(list(data.get('_links', data.get('links', {})).keys())[:5])]
                    ))
                
                if 'error' in data:
                    findings.append(Finding(
                        what="错误响应",
                        so_what="可能暴露内部路径信息",
                        evidence=[data.get('error', '')[:50]]
                    ))
        
        except (json.JSONDecodeError, TypeError):
            pass
        
        if findings:
            return Insight(
                type=InsightType.PATTERN,
                content=f"从响应中发现 {len(findings)} 个洞察",
                confidence=0.6,
                findings=findings
            )
        
        return None
    
    def _identify_opportunities(self, context: 'DiscoveryContext') -> List[Insight]:
        """识别潜在机会"""
        insights = []
        
        if len(context.discovered_endpoints) > 5:
            insights.append(Insight(
                type=InsightType.OPPORTUNITY,
                content="已收集足够端点，可以深入分析响应内容",
                confidence=0.7,
                findings=[Finding(
                    what="发现的端点足够多",
                    so_what="应该分析响应内容推导更多端点",
                    evidence=[f"已发现 {len(context.discovered_endpoints)} 个端点"]
                )]
            ))
        
        if context.tech_stack.frontend.value == "frontend_unknown":
            insights.append(Insight(
                type=InsightType.OPPORTUNITY,
                content="前端技术栈未知，需要分析 JS 确定",
                confidence=0.6,
                findings=[Finding(
                    what="技术栈识别不完整",
                    so_what="分析 JS 可以确定前端框架和 API 模式",
                    evidence=["前端框架未知"]
                )]
            ))
        
        if context.api_base and len(context.discovered_endpoints) < 3:
            insights.append(Insight(
                type=InsightType.OPPORTUNITY,
                content="已发现 API Base，应尝试常见端点",
                confidence=0.7,
                findings=[Finding(
                    what="API Base 已知",
                    so_what="可以尝试常见 REST 端点",
                    evidence=[f"API Base: {context.api_base}"]
                )]
            ))
        
        return insights
    
    def generate_with_llm(
        self,
        observations: List[Observation],
        context: 'DiscoveryContext'
    ) -> List[Insight]:
        """
        使用 LLM 生成洞察
        
        Args:
            observations: 观察列表
            context: 发现上下文
            
        Returns:
            List[Insight]: 生成的洞察
        """
        if not self.llm_client or not observations:
            return self.generate_from_observations(observations, context)
        
        obs = observations[0]
        
        prompt = LLM_INSIGHT_PROMPT.format(
            obs_type=obs.type.value,
            obs_source=obs.source,
            content_summary=str(obs.content)[:500],
            endpoints_count=len(context.discovered_endpoints),
            tech_stack=context.tech_stack.to_dict(),
            api_base=context.api_base or "unknown"
        )
        
        try:
            response = self.llm_client.generate(prompt)
            data = json.loads(response)
            
            insights = []
            for item in data.get("insights", []):
                findings = []
                for f in item.get("findings", []):
                    findings.append(Finding(
                        what=f.get("what", ""),
                        so_what=f.get("so_what", ""),
                        evidence=f.get("evidence", [])
                    ))
                
                insights.append(Insight(
                    type=InsightType(item.get("type", "pattern")),
                    content=item.get("content", ""),
                    confidence=item.get("confidence", 0.5),
                    findings=findings
                ))
            
            return insights
        
        except (json.JSONDecodeError, Exception):
            return self.generate_from_observations(observations, context)


def create_insight_generator(llm_client=None) -> InsightGenerator:
    """创建洞察生成器"""
    return InsightGenerator(llm_client=llm_client)
