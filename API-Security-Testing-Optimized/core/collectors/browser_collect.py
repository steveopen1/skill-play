"""
无头浏览器采集 - 使用Playwright进行动态采集
输入: {url, wait_until, interact, intercept_api}
输出: {apis, storage, forms, page_title}
"""

import asyncio
import re
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


async def browser_collect(config):
    """
    使用无头浏览器采集API和信息
    
    输入:
        url: string - 目标URL
        wait_until?: "networkidle" | "domcontentloaded"
        interact?: boolean - 是否模拟交互
        intercept_api?: boolean - 是否拦截API请求
    
    输出:
        apis: Array<{method, url, post_data}>
        storage: {localStorage, cookies}
        forms: Array<{action, method, inputs}>
        page_title: string
    """
    if not PLAYWRIGHT_AVAILABLE:
        return {
            'error': 'playwright_not_available',
            'apis': [],
            'storage': {},
            'forms': []
        }
    
    url = config.get('url')
    wait_until = config.get('wait_until', 'networkidle')
    interact = config.get('interact', False)
    intercept_api = config.get('intercept_api', True)
    
    result = {
        'apis': [],
        'storage': {},
        'forms': [],
        'page_title': ''
    }
    
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage']
            )
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            page = await context.new_page()
            
            # API拦截
            captured_apis = []
            
            if intercept_api:
                async def on_request(request):
                    if request.resource_type in ['xhr', 'fetch', 'document']:
                        captured_apis.append({
                            'method': request.method,
                            'url': request.url,
                            'post_data': request.post_data
                        })
                
                page.on('request', on_request)
            
            # 访问页面
            try:
                await page.goto(url, timeout=30000, wait_until=wait_until)
            except Exception as e:
                result['error'] = str(e)
            
            # 等待JS执行
            await asyncio.sleep(2)
            
            # 模拟交互
            if interact:
                try:
                    # 填写表单
                    inputs = await page.query_selector_all('input')
                    for inp in inputs[:5]:
                        try:
                            inp_type = await inp.get_attribute('type')
                            inp_name = await inp.get_attribute('name')
                            
                            if inp_type == 'text' or inp_name in ['username', 'user', 'account']:
                                await inp.fill('admin')
                            elif inp_type == 'password':
                                await inp.fill('admin123')
                        except:
                            pass
                    
                    # 点击按钮
                    buttons = await page.query_selector_all('button')
                    for btn in buttons[:5]:
                        try:
                            await btn.click()
                            await asyncio.sleep(0.3)
                        except:
                            pass
                    
                    await asyncio.sleep(1)
                except:
                    pass
            
            # 采集localStorage
            try:
                ls = await page.evaluate("""
                    () => {
                        const data = {};
                        try {
                            for (let i = 0; i < localStorage.length; i++) {
                                const key = localStorage.key(i);
                                data[key] = localStorage.getItem(key);
                            }
                        } catch (e) {}
                        return data;
                    }
                """)
                result['storage']['localStorage'] = ls
            except:
                pass
            
            # 采集Cookie
            try:
                cookies = await context.cookies()
                result['storage']['cookies'] = [
                    {'name': c['name'], 'value': c['value'][:50]} 
                    for c in cookies
                ]
            except:
                pass
            
            # 采集表单
            try:
                forms = await page.evaluate("""
                    () => {
                        const forms = [];
                        document.querySelectorAll('form').forEach(f => {
                            const formData = {
                                action: f.action,
                                method: f.method,
                                inputs: []
                            };
                            f.querySelectorAll('input').forEach(inp => {
                                formData.inputs.push({
                                    name: inp.name,
                                    type: inp.type,
                                    id: inp.id
                                });
                            });
                            forms.push(formData);
                        });
                        return forms;
                    }
                """)
                result['forms'] = forms
            except:
                pass
            
            # 采集页面标题
            try:
                result['page_title'] = await page.title()
            except:
                pass
            
            # 采集API请求
            result['apis'] = captured_apis
            
            await browser.close()
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def extract_apis_from_browser(result):
    """从浏览器采集结果中提取API"""
    apis = result.get('apis', [])
    
    # 去重
    unique_apis = {}
    for api in apis:
        url = api['url']
        if url not in unique_apis:
            unique_apis[url] = api
    
    return list(unique_apis.values())


def extract_base_url(html_content, base_url):
    """从HTML中提取API Base URL"""
    patterns = [
        r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
        r'apiBase\s*[:=]\s*["\']([^"\']+)["\']',
        r'VUE_APP_API\s*[:=]\s*["\']([^"\']+)["\']',
        r'REACT_APP_API\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    
    for pattern in patterns:
        import re
        match = re.search(pattern, html_content)
        if match:
            return match.group(1)
    
    # 默认从base_url推导
    parsed = urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}"


if __name__ == '__main__':
    # 测试
    import json
    
    async def test():
        result = await browser_collect({
            'url': 'https://example.com',
            'wait_until': 'networkidle',
            'interact': True
        })
        print(f"APIs: {len(result['apis'])}")
        print(f"Storage: {len(result['storage'])}")
        print(f"Forms: {len(result['forms'])}")
    
    asyncio.run(test())
