"""
Intelligent API Discovery - Orchestrator

主协调器，协调所有组件完成智能 API 发现

核心流程：
1. 初始化 → Agent 分析目标，建立初始上下文
2. 观察 → Collector 收集信息（Browser/Sources/Responses）
3. 推理 → Agent 从观察中生成洞察
4. 策略 → Agent 基于洞察生成新的发现策略
5. 执行 → Agent 执行策略，触发更多观察
6. 学习 → Agent 更新上下文，重复 2-5 直到收敛
"""

import asyncio
import json
import time
from typing import List, Dict, Optional, Any, Callable
from datetime import datetime
from urllib.parse import urlparse

from .models import (
    DiscoveryContext, Endpoint, Observation, Insight, Strategy, Action,
    NetworkRequest, PageStructure, ExecutionResult,
    ObservationType, InsightType, ActionType, Finding
)
from .agent_brain import AgentBrain, create_agent_brain
from .context_manager import ContextManager, create_context_manager
from .environment import EnvironmentChecker
from .collectors import (
    BrowserCollector, SourceAnalyzer, ResponseAnalyzer,
    create_browser_collector
)


class DiscoveryOrchestrator:
    """
    API 发现协调器
    
    协调 Agent Brain 和 Collectors 完成智能 API 发现
    """
    
    def __init__(
        self,
        target: str,
        llm_client=None,
        use_browser: bool = True,
        max_iterations: int = 50,
        max_duration: float = 3600.0
    ):
        """
        初始化协调器
        
        Args:
            target: 目标 URL
            llm_client: LLM 客户端
            use_browser: 是否使用浏览器
            max_iterations: 最大迭代次数
            max_duration: 最大运行时长（秒）
        """
        self.target = target
        self.use_browser = use_browser
        self.max_iterations = max_iterations
        self.max_duration = max_duration
        
        self.agent = create_agent_brain(llm_client)
        self.context_manager = create_context_manager(target)
        
        self._browser: Optional[BrowserCollector] = None
        self._source_analyzer = SourceAnalyzer(llm_client)
        self._response_analyzer = ResponseAnalyzer(llm_client)
        
        self._running = False
        self._callbacks: Dict[str, List[Callable]] = {
            'iteration': [],
            'discovery': [],
            'insight': [],
            'error': [],
            'complete': []
        }
        
        self._session = None
    
    @property
    def context(self) -> DiscoveryContext:
        """获取当前上下文"""
        return self.context_manager.context
    
    def on(self, event: str, callback: Callable):
        """
        注册事件回调
        
        Args:
            event: 事件类型 (iteration, discovery, insight, error, complete)
            callback: 回调函数
        """
        if event in self._callbacks:
            self._callbacks[event].append(callback)
    
    def _emit(self, event: str, data: Any):
        """触发事件"""
        for callback in self._callbacks.get(event, []):
            try:
                callback(data)
            except Exception:
                pass
    
    def _check_and_setup_environment(self) -> bool:
        """
        检查并设置环境依赖
        
        如果 Playwright 或系统依赖缺失，尝试自动安装。
        
        Returns:
            bool: 环境是否就绪
        """
        print("[*] Checking Playwright installation...")
        playwright_ok = EnvironmentChecker.check_playwright_installed()
        if not playwright_ok:
            print("[*] Playwright not found, installing...")
            if not EnvironmentChecker.install_playwright():
                print("[!] Failed to install Playwright")
                return False
            print("[*] Playwright installed successfully")
        
        print("[*] Checking system dependencies...")
        missing_deps = EnvironmentChecker.check_system_deps()
        if missing_deps:
            print(f"[*] Missing system deps: {missing_deps}")
            print("[*] Installing system dependencies...")
            if not EnvironmentChecker.install_system_deps():
                print("[!] Failed to install system dependencies")
                return False
            print("[*] System dependencies installed")
        
        print("[*] Checking Playwright browser...")
        browser_ok = EnvironmentChecker.check_playwright_browser()
        if not browser_ok:
            print("[*] Playwright browser not found, installing Chromium...")
            import subprocess
            try:
                result = subprocess.run(
                    ['playwright', 'install', 'chromium'],
                    capture_output=True,
                    timeout=300
                )
                if result.returncode != 0:
                    print(f"[!] Failed to install Chromium: {result.stderr.decode()}")
                    return False
                print("[*] Chromium installed successfully")
            except Exception as e:
                print(f"[!] Failed to install Chromium: {e}")
                return False
        
        print("[*] Verifying browser can launch...")
        final_check = EnvironmentChecker.check_all()
        if final_check['can_launch_browser']:
            print("[*] Environment ready for browser automation")
            return True
        else:
            print(f"[!] Environment issues: {final_check['issues']}")
            return False
    
    async def run(self) -> DiscoveryContext:
        """
        运行发现流程
        
        Returns:
            DiscoveryContext: 最终上下文
        """
        self._running = True
        start_time = time.time()
        
        print("=" * 60)
        print("Intelligent API Discovery")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Browser: {'Enabled' if self.use_browser else 'Disabled'}")
        
        if self.use_browser:
            print("\n[*] Checking environment...")
            env_ok = self._check_and_setup_environment()
            if not env_ok:
                print("[!] Browser environment not available, falling back to HTTP-only mode")
                self.use_browser = False
        
        print("=" * 60)
        
        try:
            await self._initialize()
            
            iteration = 0
            
            # 预探测阶段：测试常见 API 端点
            if not self.context_manager.converged():
                print("\n[*] Pre-scanning common API endpoints...")
                await self._probe_common_endpoints()
            
            while self._running and iteration < self.max_iterations:
                if time.time() - start_time > self.max_duration:
                    print("\n[!] Max duration reached")
                    break
                
                if self.context_manager.converged():
                    print("\n[*] Discovery converged")
                    break
                
                iteration += 1
                print(f"\n[*] Iteration {iteration}/{self.max_iterations}")
                
                observations = await self._collect()
                
                insights = self.agent.analyze(self.context, observations)
                
                for insight in insights:
                    self.context_manager.add_insight(insight)
                    self._emit('insight', insight)
                
                strategy = self.agent.generate_strategy(self.context, insights)
                
                for action in strategy.actions:
                    result = await self._execute_action(action)
                    
                    if result.observations:
                        new_insights = self.agent.analyze(self.context, result.observations)
                        for insight in new_insights:
                            self.context_manager.add_insight(insight)
                    
                    self.context_manager.record_action(action, result.success)
                    
                    if result.success and result.observations:
                        for obs in result.observations:
                            if obs.type == ObservationType.NETWORK_REQUEST:
                                if isinstance(obs.content, NetworkRequest):
                                    self.context_manager.add_network_request(obs.content)
                
                self._emit('iteration', {
                    'iteration': iteration,
                    'endpoints_count': len(self.context.discovered_endpoints),
                    'insights_count': len(self.context.insights)
                })
                
                print(f"    Endpoints: {len(self.context.discovered_endpoints)}")
                print(f"    Insights: {len(self.context.insights)}")
            
            print("\n" + "=" * 60)
            print("Discovery Complete")
            print("=" * 60)
            self._print_summary()
            
        except Exception as e:
            print(f"\n[!] Error: {e}")
            self.context_manager.add_error(str(e))
            self._emit('error', {'error': str(e)})
        
        finally:
            await self._cleanup()
            self._emit('complete', self.context)
        
        return self.context
    
    async def _probe_common_endpoints(self):
        """探测常见的 API 端点"""
        if not self._session:
            import requests
            self._session = requests.Session()
            self._session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
        
        found_count = 0
        
        # Phase 1: 探测基础端点
        common_endpoints = [
            "/prod-api/common/permission/getMenu",
            "/prod-api/common/permission/getInfo",
            "/prod-api/common/permission/getRouters",
            "/prod-api/system/user/profile",
            "/prod-api/system/user/getInfo",
            "/prod-api/system/menu/list",
            "/prod-api/system/menu/getRouters",
            "/prod-api/system/role/list",
            "/prod-api/system/dept/list",
            "/prod-api/system/user/list",
            "/prod-api/system/dict/data/list",
            "/prod-api/system/config/configKey",
            "/prod-api/system/post/list",
            "/prod-api/system/notice/list",
            "/prod-api/system/login/logout",
            "/prod-api/system/operlog/list",
            "/prod-api/system/logininfor/list",
            "/prod-api/system/dict/data/type",
            "/prod-api/monitor/online/list",
            "/prod-api/monitor/server/list",
            "/prod-api/monitor/cache/list",
            "/prod-api/getSiteList",
            "/prod-api/ws/info",
            "/prod-api/license/valid",
            "/prod-api/captchaImage",
            "/prod-api/logout",
        ]
        
        for path in common_endpoints:
            url = self.target.rstrip('/') + path
            for method in ['GET', 'POST']:
                try:
                    if method == 'GET':
                        resp = self._session.get(url, timeout=3)
                    else:
                        resp = self._session.post(url, json={}, timeout=3)
                    
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data.get('code') == 200:
                                endpoint = Endpoint(
                                    path=path,
                                    method=method,
                                    source="common_probe",
                                    confidence=0.7
                                )
                                if self.context_manager.add_endpoint(endpoint):
                                    found_count += 1
                                    print(f"    [{method}] {path}")
                        except:
                            pass
                except:
                    pass
        
        # Phase 2: 变体探测 - 资源 + 操作
        print("    [*] Probing resource variations...")
        
        resources = [
            'user', 'role', 'menu', 'dept', 'post', 'dict', 'dictData', 'dictType',
            'config', 'notice', 'log', 'operlog', 'logininfor', 'job', 'task',
            'online', 'server', 'cache', 'monitor'
        ]
        actions = ['list', 'get', 'add', 'create', 'update', 'edit', 'delete', 'remove', 'export', 'import']
        
        for resource in resources:
            for action in actions:
                path = f"/prod-api/system/{resource}/{action}"
                url = self.target.rstrip('/') + path
                try:
                    resp = self._session.post(url, json={}, timeout=2)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data.get('code') == 200:
                                endpoint = Endpoint(
                                    path=path,
                                    method="POST",
                                    source="variation_probe",
                                    confidence=0.6
                                )
                                if self.context_manager.add_endpoint(endpoint):
                                    found_count += 1
                                    print(f"    [Variation] POST {path}")
                        except:
                            pass
                except:
                    pass
        
        print(f"    Probed {found_count} endpoints total")
    
    async def _initialize(self):
        """初始化阶段"""
        print("\n[*] Initializing...")
        
        if self.use_browser:
            self._browser = await create_browser_collector(headless=True)
            if self._browser:
                print("    Browser: Started")
            else:
                print("    Browser: Failed (will use HTTP only)")
        
        try:
            import requests
            self._session = requests.Session()
            self._session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            resp = self._session.get(self.target, timeout=30)
            
            self._process_http_response(resp, self.target)
            
            print(f"    HTTP: {resp.status_code}")
            
        except Exception as e:
            print(f"    HTTP: {e}")
        
        if self._browser:
            try:
                page_structure = await self._browser.navigate(self.target)
                self.context_manager.add_page_structure(page_structure)
                
                if page_structure.title:
                    print(f"    Title: {page_structure.title[:50]}")
                
                for script in page_structure.scripts[:3]:
                    await self._analyze_script(script)
                
            except Exception as e:
                print(f"    Browser nav: {e}")
        
        self._emit('discovery', {
            'type': 'initial',
            'endpoints': [ep.to_dict() for ep in self.context.discovered_endpoints]
        })
    
    async def _collect(self) -> List[Observation]:
        """
        收集观察
        
        Returns:
            List[Observation]: 观察列表
        """
        observations = []
        
        if self._browser:
            try:
                requests = await self._browser.get_network_requests()
                for req in requests:
                    obs = Observation(
                        type=ObservationType.NETWORK_REQUEST,
                        content=req,
                        source="browser_collector"
                    )
                    observations.append(obs)
                    self.context_manager.add_network_request(req)
                
                page_structure = await self._browser.get_page_structure()
                obs = Observation(
                    type=ObservationType.PAGE_STRUCTURE,
                    content=page_structure,
                    source="browser_collector"
                )
                observations.append(obs)
                
            except Exception as e:
                pass
        
        return observations
    
    async def _execute_action(self, action: Action) -> ExecutionResult:
        """
        执行动作
        
        Args:
            action: 要执行的动作
            
        Returns:
            ExecutionResult: 执行结果
        """
        result = ExecutionResult(
            action=action,
            success=False,
            observations=[]
        )
        
        start_time = time.time()
        
        try:
            if action.type == ActionType.NAVIGATE:
                if self._browser:
                    page = await self._browser.navigate(action.target)
                    obs = Observation(
                        type=ObservationType.PAGE_STRUCTURE,
                        content=page,
                        source="navigation"
                    )
                    result.observations.append(obs)
                    self.context_manager.add_page_structure(page)
                else:
                    resp = self._session.get(action.target, timeout=10)
                    self._process_http_response(resp, action.target)
                
                result.success = True
            
            elif action.type == ActionType.CLICK:
                if self._browser:
                    obs = await self._browser.interact(
                        action.target,
                        "click"
                    )
                    result.observations.append(obs)
                    result.success = obs.type != ObservationType.ERROR
            
            elif action.type == ActionType.TYPE:
                if self._browser:
                    text = action.params.get("text", "")
                    obs = await self._browser.interact(
                        action.target,
                        "type",
                        {"text": text}
                    )
                    result.observations.append(obs)
                    result.success = obs.type != ObservationType.ERROR
            
            elif action.type == ActionType.SCROLL:
                if self._browser:
                    direction = action.params.get("direction", "down")
                    obs = await self._browser.scroll(direction)
                    result.observations.append(obs)
                    result.success = True
            
            elif action.type == ActionType.WAIT:
                seconds = action.params.get("seconds", 1)
                await asyncio.sleep(seconds)
                result.success = True
            
            elif action.type == ActionType.FETCH_API:
                response = await self._fetch_api(
                    action.target,
                    action.params.get("method", "GET"),
                    action.params.get("data")
                )
                if response:
                    obs = Observation(
                        type=ObservationType.API_RESPONSE,
                        content=response,
                        source="api_fetch"
                    )
                    result.observations.append(obs)
                    result.success = True
            
            elif action.type == ActionType.ANALYZE_SOURCE:
                if action.target == "current_page" and self._browser:
                    page = await self._browser.get_page_structure()
                    for script_url in page.scripts:
                        await self._analyze_script(script_url)
                result.success = True
            
            else:
                result.error = f"Unknown action type: {action.type}"
        
        except Exception as e:
            result.error = str(e)
            result.success = False
        
        result.duration = time.time() - start_time
        
        return result
    
    async def _fetch_api(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Dict] = None
    ) -> Optional[NetworkRequest]:
        """获取 API 响应"""
        try:
            if method == "GET":
                resp = self._session.get(url, timeout=10)
            elif method == "POST":
                resp = self._session.post(url, json=data, timeout=10)
            else:
                resp = self._session.request(method, url, timeout=10)
            
            return NetworkRequest(
                url=url,
                method=method,
                headers=dict(resp.headers),
                body=json.dumps(data) if data else None,
                response_status=resp.status_code,
                response_body=resp.text,
                response_headers=dict(resp.headers),
                timestamp=datetime.now(),
                source="api_fetch"
            )
        except Exception:
            return None
    
    async def _analyze_script(self, script_url: str):
        """分析 JS 脚本"""
        try:
            if script_url.startswith("http"):
                resp = self._session.get(script_url, timeout=10)
            else:
                resp = self._session.get(
                    self.target.rstrip('/') + '/' + script_url.lstrip('/'),
                    timeout=10
                )
            
            if resp.status_code == 200:
                result = self._source_analyzer.analyze_js(
                    resp.text,
                    self.context,
                    script_url
                )
                
                for endpoint in result.endpoints:
                    self.context_manager.add_endpoint(endpoint)
                
                for insight in result.insights:
                    self.context_manager.add_insight(insight)
                
                if result.tech_hints:
                    self.context_manager.update_tech_stack({
                        'frontend': result.tech_hints[0]
                    })
        
        except Exception:
            pass
    
    def _process_http_response(self, resp, url: str):
        """处理 HTTP 响应"""
        if 'content-type' in resp.headers:
            content_type = resp.headers['content-type'].lower()
            
            if 'application/json' in content_type:
                try:
                    result = self._response_analyzer.analyze(
                        NetworkRequest(
                            url=url,
                            method="GET",
                            headers=dict(resp.headers),
                            body=None,
                            response_status=resp.status_code,
                            response_body=resp.text,
                            response_headers=dict(resp.headers),
                            timestamp=datetime.now(),
                            source="http_discovery"
                        ),
                        self.context
                    )
                    
                    for endpoint in result.endpoints:
                        self.context_manager.add_endpoint(endpoint)
                
                except Exception:
                    pass
    
    def _print_summary(self):
        """打印发现摘要"""
        print(f"\nDiscovered Endpoints: {len(self.context.discovered_endpoints)}")
        
        high_conf = self.context_manager.get_high_confidence_endpoints()
        if high_conf:
            print(f"High Confidence: {len(high_conf)}")
            for ep in high_conf[:5]:
                print(f"  - {ep.method} {ep.path} (confidence: {ep.confidence:.2f})")
        
        if self.context.discovered_endpoints:
            print("\nAll Endpoints:")
            for ep in self.context.discovered_endpoints[:20]:
                print(f"  - {ep.method} {ep.path} (source: {ep.source})")
        
        if self.context.known_patterns:
            print(f"\nPatterns: {len(self.context.known_patterns)}")
            for pattern in self.context.known_patterns[:5]:
                print(f"  - {pattern.template}")
        
        if self.context.errors:
            print(f"\nErrors: {len(self.context.errors)}")
            for error in self.context.errors[:3]:
                print(f"  - {error}")
    
    async def _cleanup(self):
        """清理资源"""
        if self._browser:
            try:
                await self._browser.stop()
            except Exception:
                pass
        
        if self._session:
            try:
                self._session.close()
            except Exception:
                pass
    
    def stop(self):
        """停止发现"""
        self._running = False


async def run_discovery(
    target: str,
    llm_client=None,
    use_browser: bool = True,
    max_iterations: int = 50,
    max_duration: float = 3600.0
) -> DiscoveryContext:
    """
    运行智能 API 发现
    
    Args:
        target: 目标 URL
        llm_client: LLM 客户端
        use_browser: 是否使用浏览器
        max_iterations: 最大迭代次数
        max_duration: 最大运行时长
        
    Returns:
        DiscoveryContext: 最终上下文
    """
    orchestrator = DiscoveryOrchestrator(
        target=target,
        llm_client=llm_client,
        use_browser=use_browser,
        max_iterations=max_iterations,
        max_duration=max_duration
    )
    
    return await orchestrator.run()
