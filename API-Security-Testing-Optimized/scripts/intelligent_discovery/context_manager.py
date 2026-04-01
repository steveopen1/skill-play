"""
Intelligent API Discovery - Context Manager

动态上下文管理器，负责：
1. 维护和更新发现上下文
2. 管理端点、模式、网络请求等数据
3. 跟踪探索历史和学习状态
"""

from typing import List, Dict, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime

from .models import (
    DiscoveryContext, Endpoint, Observation, Insight, Strategy, Action,
    NetworkRequest, Pattern, PageStructure, TechStack, AuthInfo,
    ObservationType, InsightType, ActionType, Finding, Service
)


class ContextManager:
    """
    发现上下文管理器
    
    负责维护和更新 API 发现的上下文状态
    """
    
    def __init__(self, target: str):
        """
        初始化上下文管理器
        
        Args:
            target: 目标 URL
        """
        self._context = DiscoveryContext(target=target)
        self._action_results: List[Dict] = []
        self._discovered_urls: Set[str] = set()
    
    @property
    def context(self) -> DiscoveryContext:
        """获取当前上下文"""
        return self._context
    
    def update_tech_stack(self, tech_info: Dict[str, Any]):
        """
        更新技术栈信息
        
        Args:
            tech_info: 技术栈信息字典
        """
        if 'frontend' in tech_info:
            self._context.tech_stack.frontend = self._parse_frontend_type(tech_info['frontend'])
        
        if 'backend' in tech_info:
            self._context.tech_stack.backend = self._parse_backend_type(tech_info['backend'])
        
        if 'api_style' in tech_info:
            if isinstance(tech_info['api_style'], list):
                self._context.tech_stack.api_style.update(tech_info['api_style'])
            else:
                self._context.tech_stack.api_style.add(tech_info['api_style'])
        
        if 'waf' in tech_info:
            self._context.tech_stack.waf = tech_info['waf']
    
    def add_endpoint(self, endpoint: Endpoint) -> bool:
        """
        添加发现的端点
        
        Returns:
            bool: 是否新增（去重）
        """
        key = f"{endpoint.method}:{endpoint.path}"
        
        if key in self._discovered_urls:
            return False
        
        self._discovered_urls.add(key)
        self._context.discovered_endpoints.append(endpoint)
        return True
    
    def add_network_request(self, request: NetworkRequest):
        """添加网络请求"""
        self._context.network_requests.append(request)
        
        if request.is_api:
            endpoint = Endpoint(
                path=self._extract_path(request.url),
                method=request.method,
                source="network_capture",
                confidence=0.9
            )
            self.add_endpoint(endpoint)
    
    def add_pattern(self, pattern: Pattern):
        """添加发现的模式"""
        self._context.known_patterns.append(pattern)
    
    def add_insight(self, insight: Insight):
        """添加洞察"""
        self._context.insights.append(insight)
    
    def record_action(self, action: Action, success: bool = True):
        """
        记录执行的动作
        
        Args:
            action: 执行的动作
            success: 是否成功
        """
        action.executed_at = datetime.now()
        action.success = success
        self._context.exploration_history.append(action)
        
        self._action_results.append({
            "action": action.to_dict(),
            "success": success,
            "timestamp": action.executed_at.isoformat()
        })
    
    def add_error(self, error: str):
        """添加错误"""
        self._context.errors.append(error)
    
    def set_api_base(self, api_base: str):
        """设置 API 基础地址"""
        self._context.api_base = api_base
    
    def update_auth_info(self, auth_info: AuthInfo):
        """更新认证信息"""
        self._context.auth_info = auth_info
    
    def add_internal_ip(self, ip: str):
        """添加发现的内部 IP"""
        if ip not in self._context.internal_ips:
            self._context.internal_ips.append(ip)
    
    def add_page_structure(self, page: PageStructure):
        """添加页面结构"""
        self._context.page_structures.append(page)
    
    def add_service(self, service: Service):
        """添加微服务信息"""
        self._context.micro_services.append(service)
    
    def update_confidence(self, key: str, confidence: float):
        """
        更新置信度
        
        Args:
            key: 标识键
            confidence: 置信度值 (0.0-1.0)
        """
        self._context.confidence_scores[key] = confidence
    
    def get_confidence(self, key: str) -> float:
        """
        获取置信度
        
        Args:
            key: 标识键
            
        Returns:
            float: 置信度值，默认 0.5
        """
        return self._context.confidence_scores.get(key, 0.5)
    
    def converged(self) -> bool:
        """
        判断发现是否已收敛
        
        当探索历史足够长但发现新端点很少时，认为收敛
        """
        return self._context.converged()
    
    def get_high_confidence_endpoints(self, threshold: float = 0.7) -> List[Endpoint]:
        """
        获取高置信度端点
        
        Args:
            threshold: 置信度阈值
            
        Returns:
            List[Endpoint]: 高置信度端点列表
        """
        return [
            ep for ep in self._context.discovered_endpoints
            if ep.confidence >= threshold
        ]
    
    def get_summary(self) -> Dict[str, Any]:
        """
        获取上下文摘要
        
        Returns:
            Dict: 上下文摘要
        """
        return {
            "target": self._context.target,
            "endpoints_count": len(self._context.discovered_endpoints),
            "high_confidence_count": len(self.get_high_confidence_endpoints()),
            "patterns_count": len(self._context.known_patterns),
            "api_base": self._context.api_base,
            "tech_stack": self._context.tech_stack.to_dict(),
            "exploration_count": len(self._context.exploration_history),
            "network_requests_count": len(self._context.network_requests),
            "insights_count": len(self._context.insights),
            "errors_count": len(self._context.errors),
            "converged": self.converged()
        }
    
    def export_context(self) -> DiscoveryContext:
        """导出完整上下文"""
        return self._context
    
    def _extract_path(self, url: str) -> str:
        """从 URL 提取路径"""
        from urllib.parse import urlparse
        if url.startswith("http"):
            return urlparse(url).path or "/"
        if url.startswith("/"):
            return url
        return "/" + url
    
    def _parse_frontend_type(self, value: str):
        """解析前端技术栈类型"""
        from .models import TechStackType
        mapping = {
            'react': TechStackType.REACT,
            'vue': TechStackType.VUE,
            'angular': TechStackType.ANGULAR,
            'next': TechStackType.NEXTJS,
            'nuxt': TechStackType.NUXT,
            'vanilla': TechStackType.VANILLA,
        }
        return mapping.get(value.lower(), TechStackType.FRONTEND_UNKNOWN)
    
    def _parse_backend_type(self, value: str):
        """解析后端技术栈类型"""
        from .models import TechStackType
        mapping = {
            'express': TechStackType.EXPRESS,
            'fastapi': TechStackType.FASTAPI,
            'django': TechStackType.DJANGO,
            'flask': TechStackType.FLASK,
            'spring': TechStackType.SPRING,
            'nest': TechStackType.NESTJS,
            'golang': TechStackType.GOLANG,
        }
        return mapping.get(value.lower(), TechStackType.BACKEND_UNKNOWN)


def create_context_manager(target: str) -> ContextManager:
    """创建上下文管理器"""
    return ContextManager(target)
