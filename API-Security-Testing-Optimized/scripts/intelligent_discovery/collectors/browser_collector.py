"""
Intelligent API Discovery - Browser Collector

动态交互引擎，负责：
1. 控制浏览器与页面交互
2. 监控和捕获网络请求
3. 获取页面结构信息

注意：这是工具而非决策者，具体交互策略由 Agent Brain 控制
"""

from __future__ import annotations

import asyncio
import json
from typing import List, Dict, Optional, Any, Callable, Set, TYPE_CHECKING
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse

try:
    from playwright.async_api import async_playwright, Browser, Page, Request, Response
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from ..models import (
    NetworkRequest, PageStructure, Observation, ObservationType, Action, ActionType
)


@dataclass
class InterceptedRequest:
    """拦截的请求"""
    request: 'Request'
    response: Optional['Response']
    timestamp: datetime = field(default_factory=datetime.now)


class BrowserCollector:
    """
    浏览器采集器
    
    提供浏览器控制能力，由 Agent Brain 决策如何使用
    
    核心能力：
    - navigate: 导航到 URL
    - get_page_structure: 获取页面结构
    - identify_interactive_elements: 识别可交互元素
    - interact: 与元素交互
    - monitor_network: 监控网络请求
    - get_network_requests: 获取捕获的请求
    """
    
    def __init__(
        self,
        headless: bool = True,
        timeout: int = 60000,
        user_agent: Optional[str] = None
    ):
        """
        初始化浏览器采集器
        
        Args:
            headless: 是否使用无头模式
            timeout: 超时时间（毫秒），默认60秒，适用于SPA应用
            user_agent: 自定义 User-Agent
        """
        self.headless = headless
        self.timeout = timeout
        
        self._browser: Optional[Browser] = None
        self._page: Optional[Page] = None
        self._playwright = None
        
        self._intercepted_requests: List[InterceptedRequest] = []
        self._current_url: str = ""
        self._user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        
        self._observers: List[Callable[[Observation], None]] = []
    
    async def start(self) -> bool:
        """
        启动浏览器
        
        Returns:
            bool: 是否启动成功
        """
        if not HAS_PLAYWRIGHT:
            print("Warning: Playwright not installed, browser collector disabled")
            return False
        
        try:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=self.headless
            )
            context = await self._browser.new_context(
                user_agent=self._user_agent,
                viewport={"width": 1920, "height": 1080}
            )
            self._page = await context.new_page()
            
            self._page.on("request", self._on_request)
            self._page.on("response", self._on_response)
            
            return True
        except Exception as e:
            print(f"Failed to start browser: {e}")
            return False
    
    async def stop(self):
        """停止浏览器"""
        if self._page:
            await self._page.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        
        self._browser = None
        self._page = None
        self._playwright = None
    
    async def navigate(self, url: str) -> PageStructure:
        """
        导航到 URL
        
        Args:
            url: 目标 URL
            
        Returns:
            PageStructure: 页面结构信息
        """
        if not self._page:
            raise RuntimeError("Browser not started")
        
        self._intercepted_requests.clear()
        
        response = await self._page.goto(url, timeout=self.timeout)
        self._current_url = url
        
        await self._page.wait_for_load_state("networkidle", timeout=30000)
        
        await asyncio.sleep(2)
        
        return await self.get_page_structure()
    
    async def get_page_structure(self) -> PageStructure:
        """
        获取当前页面结构
        
        Returns:
            PageStructure: 页面结构信息
        """
        if not self._page:
            raise RuntimeError("Browser not started")
        
        title = await self._page.title()
        url = self._page.url
        
        interactive_elements = await self._identify_interactive_elements()
        forms = await self._identify_forms()
        links = await self._extract_links()
        scripts = await self._extract_scripts()
        stylesheets = await self._extract_stylesheets()
        
        return PageStructure(
            url=url,
            title=title,
            interactive_elements=interactive_elements,
            forms=forms,
            links=links,
            scripts=scripts,
            stylesheets=stylesheets
        )
    
    async def _identify_interactive_elements(self) -> List[Dict[str, Any]]:
        """识别页面上的可交互元素"""
        selectors = {
            "button": "button",
            "link": "a[href]",
            "input_text": "input[type='text'], input:not([type])",
            "input_password": "input[type='password']",
            "input_checkbox": "input[type='checkbox'], input[type='radio']",
            "select": "select",
            "textarea": "textarea",
        }
        
        elements = []
        seen_selectors: Set[str] = set()
        
        for elem_type, selector in selectors.items():
            try:
                if elem_type == "link":
                    hrefs = await self._page.eval_on_all_elements(
                        selector,
                        "elements => elements.map(el => el.href)"
                    )
                    for href in hrefs:
                        if href and href not in seen_selectors:
                            seen_selectors.add(href)
                            elements.append({
                                "selector": f"a[href='{href}']",
                                "type": "link",
                                "action": "click",
                                "description": f"Link to {urlparse(href).path}",
                                "url": href
                            })
                else:
                    count = await self._page.locator(selector).count()
                    if count > 0 and count <= 50:
                        for i in range(min(count, 10)):
                            locator = self._page.locator(selector).nth(i)
                            tag = await locator.evaluate("el => el.tagName.toLowerCase()")
                            text = await locator.inner_text()
                            id_attr = await locator.get_attribute("id")
                            class_attr = await locator.get_attribute("class")
                            
                            selector_str = f"{tag}#{id_attr}" if id_attr else f"{tag}.{class_attr.split()[0]}" if class_attr else selector
                            
                            elements.append({
                                "selector": selector_str,
                                "type": elem_type,
                                "action": "click" if elem_type == "button" else "type",
                                "description": text[:50] if text else f"{elem_type} element",
                                "count": count
                            })
            except Exception:
                pass
        
        return elements[:30]
    
    async def _identify_forms(self) -> List[Dict[str, Any]]:
        """识别页面上的表单"""
        forms = []
        
        try:
            form_count = await self._page.locator("form").count()
            for i in range(min(form_count, 10)):
                form = self._page.locator("form").nth(i)
                
                action = await form.get_attribute("action")
                method = await form.get_attribute("method") or "GET"
                
                inputs = await form.locator("input").evaluate_all(
                    "els => els.map(el => ({"
                    "name: el.name, "
                    "type: el.type, "
                    "id: el.id"
                    "}))"
                )
                
                forms.append({
                    "selector": f"form:nth-of-type({i+1})",
                    "action": action,
                    "method": method.upper(),
                    "fields": [inp["name"] for inp in inputs if inp.get("name")]
                })
        except Exception:
            pass
        
        return forms
    
    async def _extract_links(self) -> List[str]:
        """提取页面链接"""
        links = []
        
        try:
            hrefs = await self._page.eval_on_all_elements(
                "a[href]",
                "elements => elements.map(el => el.href)"
            )
            links = list(set(hrefs))
        except Exception:
            pass
        
        return links[:50]
    
    async def _extract_scripts(self) -> List[str]:
        """提取 JS 文件 URL"""
        scripts = []
        
        try:
            srcs = await self._page.eval_on_all_elements(
                "script[src]",
                "elements => elements.map(el => el.src)"
            )
            scripts = list(set(srcs))
        except Exception:
            pass
        
        return scripts
    
    async def _extract_stylesheets(self) -> List[str]:
        """提取 CSS 文件 URL"""
        styles = []
        
        try:
            hrefs = await self._page.eval_on_all_elements(
                "link[rel='stylesheet']",
                "elements => elements.map(el => el.href)"
            )
            styles = list(set(hrefs))
        except Exception:
            pass
        
        return styles
    
    async def interact(
        self,
        selector: str,
        action: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Observation:
        """
        与元素交互
        
        Args:
            selector: 元素选择器
            action: 动作类型 (click, type, hover, submit)
            params: 动作参数
            
        Returns:
            Observation: 交互结果观察
        """
        if not self._page:
            raise RuntimeError("Browser not started")
        
        params = params or {}
        self._intercepted_requests.clear()
        
        try:
            locator = self._page.locator(selector)
            
            if action == "click":
                await locator.click(timeout=5000)
            elif action == "type":
                text = params.get("text", "")
                await locator.fill(text)
            elif action == "hover":
                await locator.hover()
            elif action == "submit":
                await locator.press("Enter")
            
            await asyncio.sleep(0.5)
            
            requests = self.get_network_requests()
            
            return Observation(
                type=ObservationType.USER_INTERACTION,
                content={
                    "selector": selector,
                    "action": action,
                    "requests": [r.to_dict() for r in requests]
                },
                source="browser_interaction"
            )
        except Exception as e:
            return Observation(
                type=ObservationType.ERROR,
                content={"selector": selector, "action": action, "error": str(e)},
                source="browser_interaction"
            )
    
    async def scroll(
        self,
        direction: str = "down",
        amount: int = 500
    ) -> Observation:
        """
        滚动页面
        
        Args:
            direction: 滚动方向 (up, down, left, right)
            amount: 滚动距离（像素）
            
        Returns:
            Observation: 滚动结果
        """
        if not self._page:
            raise RuntimeError("Browser not started")
        
        self._intercepted_requests.clear()
        
        try:
            if direction == "down":
                await self._page.mouse.wheel(0, amount)
            elif direction == "up":
                await self._page.mouse.wheel(0, -amount)
            elif direction == "left":
                await self._page.mouse.wheel(-amount, 0)
            elif direction == "right":
                await self._page.mouse.wheel(amount, 0)
            
            await asyncio.sleep(1)
            
            requests = await self.get_network_requests()
            new_structure = await self.get_page_structure()
            
            return Observation(
                type=ObservationType.PAGE_STRUCTURE,
                content=new_structure,
                source="browser_scroll"
            )
        except Exception as e:
            return Observation(
                type=ObservationType.ERROR,
                content={"error": str(e)},
                source="browser_scroll"
            )
    
    async def wait(self, seconds: float):
        """等待指定秒数"""
        await asyncio.sleep(seconds)
    
    async def get_network_requests(self) -> List[NetworkRequest]:
        """
        获取捕获的网络请求
        
        Returns:
            List[NetworkRequest]: 网络请求列表
        """
        requests = []
        
        for intercepted in self._intercepted_requests:
            req = intercepted.request
            resp = intercepted.response
            
            headers = {}
            for key, value in req.headers.items():
                headers[key] = value
            
            body = None
            try:
                if req.post_data:
                    body = req.post_data
            except Exception:
                pass
            
            response_headers = {}
            response_body = None
            status = 0
            
            if resp:
                for key, value in resp.headers.items():
                    response_headers[key] = value
                try:
                    response_body = await resp.text()
                except Exception:
                    pass
                status = resp.status
            
            requests.append(NetworkRequest(
                url=req.url,
                method=req.method,
                headers=headers,
                body=body,
                response_status=status,
                response_body=response_body,
                response_headers=response_headers,
                timestamp=intercepted.timestamp,
                source="browser_capture"
            ))
        
        return requests
    
    def _on_request(self, request: Request):
        """请求拦截回调"""
        pass
    
    def _on_response(self, response: Response):
        """响应拦截回调"""
        intercepted = InterceptedRequest(
            request=response.request,
            response=response,
            timestamp=datetime.now()
        )
        self._intercepted_requests.append(intercepted)
    
    async def click_and_intercept(self, selector: str) -> List[NetworkRequest]:
        """
        点击元素并拦截请求
        
        Args:
            selector: 元素选择器
            
        Returns:
            List[NetworkRequest]: 点击过程中产生的网络请求
        """
        self._intercepted_requests.clear()
        
        await self._page.locator(selector).click()
        await self._page.wait_for_load_state("networkidle", timeout=5000)
        
        return await self.get_network_requests()
    
    async def fill_form(
        self,
        form_data: Dict[str, str],
        submit: bool = True
    ) -> Observation:
        """
        填写表单
        
        Args:
            form_data: 表单数据 {selector: value}
            submit: 是否提交
            
        Returns:
            Observation: 表单填写结果
        """
        if not self._page:
            raise RuntimeError("Browser not started")
        
        self._intercepted_requests.clear()
        
        try:
            for selector, value in form_data.items():
                try:
                    await self._page.locator(selector).fill(value)
                except Exception:
                    pass
            
            if submit:
                await self._page.locator("button[type='submit'], button[type='button']").first.click()
                await asyncio.sleep(2)
            
            requests = await self.get_network_requests()
            
            return Observation(
                type=ObservationType.USER_INTERACTION,
                content={
                    "action": "fill_form",
                    "requests": [r.to_dict() for r in requests]
                },
                source="browser_form"
            )
        except Exception as e:
            return Observation(
                type=ObservationType.ERROR,
                content={"error": str(e)},
                source="browser_form"
            )


async def create_browser_collector(
    headless: bool = True,
    timeout: int = 60000
) -> Optional[BrowserCollector]:
    """
    创建浏览器采集器
    
    Returns:
        BrowserCollector or None if playwright not available
    """
    collector = BrowserCollector(headless=headless, timeout=timeout)
    
    if await collector.start():
        return collector
    
    return None
