#!/usr/bin/env python3
"""
JS采集 - Playwright强制模式
【禁止降级】本脚本必须成功执行Playwright采集，不允许降级到其他方案
"""

import sys
import logging
from typing import Dict

logger = logging.getLogger(__name__)

def collect_with_playwright(url: str) -> Dict:
    """
    使用Playwright进行JS采集
    【强制】不允许降级，如果Playwright失败必须报告错误
    """
    from playwright.sync_api import sync_playwright
    
    result = {
        'apis': set(),
        'configs': set(),
        'tokens': set(),
        'urls': set(),
        'traffic': [],
        'method': 'playwright',
        'error': None
    }
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            
            traffic = []
            
            def on_request(request):
                traffic.append({
                    'url': request.url,
                    'method': request.method,
                    'type': request.resource_type
                })
            
            def on_response(response):
                pass
            
            page.on('request', on_request)
            
            # 访问目标URL
            page.goto(url, wait_until='networkidle', timeout=60000)
            page.wait_for_timeout(5000)
            
            # 模拟用户交互
            try:
                page.click('body')
                page.wait_for_timeout(1000)
            except:
                pass
            
            try:
                page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
                page.wait_for_timeout(2000)
            except:
                pass
            
            # 尝试导航到登录页
            try:
                if '/user.html' not in page.url and '/login' not in page.url:
                    login_url = url.rstrip('/') + '/user.html#/pages/frame/login'
                    page.goto(login_url, wait_until='networkidle', timeout=30000)
                    page.wait_for_timeout(3000)
            except:
                pass
            
            result['traffic'] = traffic
            result['final_url'] = page.url
            
            browser.close()
            return result
            
    except Exception as e:
        result['error'] = str(e)
        return result


def analyze_js_content(content: str, result: Dict):
    """分析JS内容提取API和配置"""
    import re
    
    # API路径提取
    api_patterns = [
        r'["\'](/[a-zA-Z0-9_/.-]+)["\']',
        r'"(/callComponent/[^"]+)"',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'fetch\(["\']([^"\']+)["\']',
    ]
    
    for p in api_patterns:
        matches = re.findall(p, content)
        for m in matches:
            if isinstance(m, str) and len(m) > 2 and '/' in m:
                result['apis'].add(m)
    
    # 配置提取
    config_patterns = [
        r'baseURL["\s:]+["\']([^"\']+)["\']',
        r'VUE_APP_\w+["\s:]+["\']([^"\']*)["\']',
        r'APP-ID["\s:]+["\']([^"\']*)["\']',
    ]
    
    for p in config_patterns:
        matches = re.findall(p, content, re.IGNORECASE)
        for m in matches:
            if m:
                result['configs'].add(m)


def main():
    if len(sys.argv) < 2:
        print("Usage: python js_collector.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    
    print(f"开始Playwright采集: {url}")
    result = collect_with_playwright(url)
    
    if result['error']:
        print(f"【错误】Playwright采集失败: {result['error']}")
        print("【强制要求】不允许降级到其他方案，请修复环境问题")
        sys.exit(1)
    
    print(f"采集完成!")
    print(f"最终URL: {result.get('final_url', 'N/A')}")
    print(f"请求数量: {len(result['traffic'])}")
    
    # 统计
    by_type = {}
    for t in result['traffic']:
        typ = t.get('type', 'unknown')
        by_type[typ] = by_type.get(typ, 0) + 1
    print(f"类型分布: {by_type}")
    
    xhr = [t for t in result['traffic'] if t.get('type') == 'xhr']
    print(f"XHR请求: {len(xhr)}")
    for t in xhr[:10]:
        print(f"  {t['method']} {t['url'][:100]}")
    
    return result


if __name__ == '__main__':
    main()
