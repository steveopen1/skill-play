"""
Intelligent API Discovery - 数据模型

定义智能 API 发现系统使用的基础数据结构
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse


class ObservationType(Enum):
    """观察类型"""
    NETWORK_REQUEST = "network_request"
    PAGE_STRUCTURE = "page_structure"
    JS_CONTENT = "js_content"
    CSS_CONTENT = "css_content"
    HTML_CONTENT = "html_content"
    API_RESPONSE = "api_response"
    USER_INTERACTION = "user_interaction"
    ERROR = "error"


class InsightType(Enum):
    """洞察类型"""
    PATTERN = "pattern"
    ENDPOINT = "endpoint"
    TECH_STACK = "tech_stack"
    AUTH_REQUIRED = "auth_required"
    RATE_LIMIT = "rate_limit"
    BLOCKER = "blocker"
    OPPORTUNITY = "opportunity"
    STRATEGY = "strategy"


class ActionType(Enum):
    """动作类型"""
    NAVIGATE = "navigate"
    CLICK = "click"
    TYPE = "type"
    SCROLL = "scroll"
    HOVER = "hover"
    WAIT = "wait"
    SUBMIT = "submit"
    FETCH_API = "fetch_api"
    ANALYZE_SOURCE = "analyze_source"


class TechStackType(Enum):
    """技术栈类型"""
    FRONTEND_UNKNOWN = "frontend_unknown"
    REACT = "react"
    VUE = "vue"
    ANGULAR = "angular"
    VANILLA = "vanilla"
    NEXTJS = "nextjs"
    NUXT = "nuxt"
    
    BACKEND_UNKNOWN = "backend_unknown"
    EXPRESS = "express"
    FASTAPI = "fastapi"
    DJANGO = "django"
    FLASK = "flask"
    SPRING = "spring"
    NESTJS = "nestjs"
    GOLANG = "golang"
    
    API_GATEWAY = "api_gateway"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"


@dataclass
class Param:
    """API 参数"""
    name: str
    location: str  # query, path, body, header
    required: bool
    param_type: str  # string, number, boolean, object, array
    description: Optional[str] = None


@dataclass
class Endpoint:
    """发现的 API 端点"""
    path: str
    method: str = "GET"
    source: str = "unknown"
    confidence: float = 0.5
    auth_required: bool = False
    params: List[Param] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)
    
    @property
    def url(self) -> str:
        return f"{self.method} {self.path}"
    
    def to_dict(self) -> Dict:
        return {
            "path": self.path,
            "method": self.method,
            "source": self.source,
            "confidence": self.confidence,
            "auth_required": self.auth_required,
            "params": [
                {"name": p.name, "location": p.location, "required": p.required}
                for p in self.params
            ],
            "discovered_at": self.discovered_at.isoformat()
        }


@dataclass
class Pattern:
    """发现的 URL 模式"""
    template: str
    example: str
    confidence: float
    discovered_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "template": self.template,
            "example": self.example,
            "confidence": self.confidence,
            "discovered_at": self.discovered_at.isoformat()
        }


@dataclass
class NetworkRequest:
    """网络请求"""
    url: str
    method: str
    headers: Dict[str, str]
    body: Optional[str]
    response_status: int
    response_body: Optional[str]
    response_headers: Dict[str, str]
    timestamp: datetime
    source: str  # browser, source_analysis, inference
    
    @property
    def is_api(self) -> bool:
        if not self.url:
            return False
        parsed = urlparse(self.url)
        path = parsed.path.lower()
        return (
            "/api/" in path or
            "/rest/" in path or
            path.endswith("/graphql") or
            ".json" in path or
            "application/json" in self.response_headers.get("content-type", "")
        )
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "method": self.method,
            "response_status": self.response_status,
            "is_api": self.is_api,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source
        }


@dataclass
class Finding:
    """洞察发现"""
    what: str
    so_what: str
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.5


@dataclass
class Insight:
    """洞察"""
    type: InsightType
    content: str
    confidence: float
    findings: List[Finding] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "type": self.type.value,
            "content": self.content,
            "confidence": self.confidence,
            "findings": [
                {"what": f.what, "so_what": f.so_what, "evidence": f.evidence}
                for f in self.findings
            ],
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class Action:
    """Agent 执行的动作"""
    type: ActionType
    target: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    expected_outcome: str = ""
    executed_at: Optional[datetime] = None
    result: Optional[Any] = None
    success: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "type": self.type.value,
            "target": self.target,
            "params": self.params,
            "reasoning": self.reasoning,
            "success": self.success
        }


@dataclass
class Strategy:
    """发现策略"""
    actions: List[Action]
    reasoning: str
    expected_outcome: str
    confidence: float = 0.5
    
    def to_dict(self) -> Dict:
        return {
            "actions": [a.to_dict() for a in self.actions],
            "reasoning": self.reasoning,
            "expected_outcome": self.expected_outcome,
            "confidence": self.confidence
        }


@dataclass
class TechStack:
    """技术栈信息"""
    frontend: TechStackType = TechStackType.FRONTEND_UNKNOWN
    backend: TechStackType = TechStackType.BACKEND_UNKNOWN
    api_style: Set[str] = field(default_factory=set)  # rest, graphql, websocket, etc.
    waf: Optional[str] = None
    framework_versions: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "frontend": self.frontend.value,
            "backend": self.backend.value,
            "api_style": list(self.api_style),
            "waf": self.waf,
            "framework_versions": self.framework_versions
        }


@dataclass
class AuthInfo:
    """认证信息"""
    type: Optional[str] = None  # jwt, cookie, basic, bearer, etc.
    required: bool = False
    token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "required": self.required,
            "has_token": bool(self.token),
            "has_cookies": bool(self.cookies)
        }


@dataclass
class PageStructure:
    """页面结构"""
    url: str
    title: str
    interactive_elements: List[Dict[str, Any]] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    stylesheets: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "title": self.title,
            "interactive_elements_count": len(self.interactive_elements),
            "forms_count": len(self.forms),
            "links_count": len(self.links),
            "scripts_count": len(self.scripts)
        }


@dataclass
class Service:
    """微服务信息"""
    name: str
    base_url: str
    internal: bool = False
    related_endpoints: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "base_url": self.base_url,
            "internal": self.internal,
            "related_endpoints": self.related_endpoints
        }


@dataclass
class ExecutionResult:
    """执行结果"""
    action: Action
    success: bool
    observations: List['Observation'] = field(default_factory=list)
    error: Optional[str] = None
    duration: float = 0.0


@dataclass
class Observation:
    """观察"""
    type: ObservationType
    content: Any
    source: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "type": self.type.value,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }


@dataclass
class DiscoveryContext:
    """发现上下文"""
    target: str
    tech_stack: TechStack = field(default_factory=TechStack)
    discovered_endpoints: List[Endpoint] = field(default_factory=list)
    known_patterns: List[Pattern] = field(default_factory=list)
    api_base: Optional[str] = None
    auth_info: AuthInfo = field(default_factory=AuthInfo)
    internal_ips: List[str] = field(default_factory=list)
    micro_services: List[Service] = field(default_factory=list)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    exploration_history: List[Action] = field(default_factory=list)
    page_structures: List[PageStructure] = field(default_factory=list)
    network_requests: List[NetworkRequest] = field(default_factory=list)
    insights: List[Insight] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    _endpoint_urls: Set[str] = field(default_factory=set, repr=False)
    
    def __post_init__(self):
        self._endpoint_urls = set()
    
    def add_endpoint(self, endpoint: Endpoint) -> bool:
        """添加端点，返回是否新增（去重）"""
        key = f"{endpoint.method}:{endpoint.path}"
        if key not in self._endpoint_urls:
            self._endpoint_urls.add(key)
            self.discovered_endpoints.append(endpoint)
            return True
        return False
    
    def add_network_request(self, request: NetworkRequest):
        """添加网络请求"""
        self.network_requests.append(request)
    
    def add_pattern(self, pattern: Pattern):
        """添加发现的模式"""
        self.known_patterns.append(pattern)
    
    def add_insight(self, insight: Insight):
        """添加洞察"""
        self.insights.append(insight)
    
    def record_action(self, action: Action):
        """记录执行的动作"""
        self.exploration_history.append(action)
    
    def add_error(self, error: str):
        """添加错误"""
        self.errors.append(error)
    
    def converged(self) -> bool:
        """判断发现是否已收敛
        
        收敛条件：
        1. 探索次数超过50次
        2. 最近10次动作中动作类型单一（<=2种）且没有发现新端点
        3. 或者发现超过20个端点
        """
        if len(self.exploration_history) >= 50:
            return True
        
        # 如果还没有发现端点，不收敛
        if len(self.discovered_endpoints) == 0:
            return False
        
        # 如果发现了较多端点，认为可以收敛了
        if len(self.discovered_endpoints) >= 20:
            return True
        
        # 检查最近动作的重复度
        if len(self.exploration_history) >= 10:
            recent = self.exploration_history[-10:]
            unique_actions = len(set(a.type for a in recent))
            
            # 如果动作太单一且探索次数足够
            if unique_actions <= 2 and len(self.exploration_history) >= 20:
                return True
        
        return False
    
    def get_high_confidence_endpoints(self, threshold: float = 0.7) -> List[Endpoint]:
        """获取高置信度端点"""
        return [ep for ep in self.discovered_endpoints if ep.confidence >= threshold]
    
    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "tech_stack": self.tech_stack.to_dict(),
            "endpoints_count": len(self.discovered_endpoints),
            "patterns_count": len(self.known_patterns),
            "api_base": self.api_base,
            "auth": self.auth_info.to_dict(),
            "internal_ips": self.internal_ips,
            "micro_services": [s.to_dict() for s in self.micro_services],
            "exploration_count": len(self.exploration_history),
            "insights_count": len(self.insights),
            "errors_count": len(self.errors),
            "converged": self.converged()
        }


@dataclass
class AnalysisResult:
    """分析结果"""
    endpoints: List[Endpoint] = field(default_factory=list)
    patterns: List[Pattern] = field(default_factory=list)
    insights: List[Insight] = field(default_factory=list)
    tech_stack_hints: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
