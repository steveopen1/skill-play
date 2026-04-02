"""
无头浏览器采集 - 使用Playwright进行动态采集
输入: {url, wait_until, interact, intercept_api}
输出: {apis, storage, forms, page_title, js_files, tech_stack}

【重要】SPA采集完整流程：
1. browser_collect 采集JS文件和API
2. js_parser 分析JS提取API端点和baseURL配置
3. api_parser 解析端点
4. http_client 测试发现的API
"""

import asyncio
import re
import json
from urllib.parse import urlparse

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


def browser_collect(config):
    """
    使用无头浏览器采集API和信息（同步版本）
    
    输入:
        url: string - 目标URL
        wait_until?: "networkidle" | "domcontentloaded"
        interact?: boolean - 是否模拟交互
        intercept_api?: boolean - 是否拦截API请求
        extract_js_files?: boolean - 是否提取JS文件列表
    
    输出:
        apis: Array<{method, url, post_data}>
        storage: {localStorage, cookies}
        forms: Array<{action, method, inputs}>
        page_title: string
        js_files: Array<string> - JS文件路径列表
        tech_stack: Array<string> - 检测到的技术栈
    """
    if not PLAYWRIGHT_AVAILABLE:
        return {
            'error': 'playwright_not_available',
            'apis': [],
            'storage': {},
            'forms': [],
            'js_files': [],
            'tech_stack': []
        }
    
    url = config.get('url')
    wait_until = config.get('wait_until', 'networkidle')
    interact = config.get('interact', False)
    intercept_api = config.get('intercept_api', True)
    extract_js_files = config.get('extract_js_files', True)
    
    result = {
        'apis': [],
        'storage': {},
        'forms': [],
        'page_title': '',
        'js_files': [],
        'tech_stack': []
    }
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage']
            )
            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                ignore_https_errors=True
            )
            page = context.new_page()
            
            # API拦截
            captured_apis = []
            
            if intercept_api:
                def on_request(request):
                    if request.resource_type in ['xhr', 'fetch', 'document']:
                        captured_apis.append({
                            'method': request.method,
                            'url': request.url,
                            'post_data': request.post_data
                        })
                
                page.on('request', on_request)
            
            # 访问页面
            try:
                response = page.goto(url, timeout=60000, wait_until=wait_until)
                result['status_code'] = response.status if response else None
            except Exception as e:
                result['error'] = str(e)
            
            # 等待JS执行（关键！必须等待）
            page.wait_for_timeout(5000)
            
            # 提取JS文件列表（关键！）
            if extract_js_files:
                try:
                    html_content = page.content()
                    js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html_content)
                    result['js_files'] = js_files
                    
                    # 检测技术栈
                    tech = []
                    if 'vue' in html_content.lower(): tech.append('Vue')
                    if 'react' in html_content.lower(): tech.append('React')
                    if 'angular' in html_content.lower(): tech.append('Angular')
                    if 'webpack' in html_content.lower(): tech.append('Webpack')
                    if 'element-ui' in html_content.lower(): tech.append('ElementUI')
                    if 'ant-design' in html_content.lower(): tech.append('AntDesign')
                    result['tech_stack'] = tech
                except Exception as e:
                    result['js_extract_error'] = str(e)
            
            # 模拟交互
            if interact:
                try:
                    inputs = page.query_selector_all('input')
                    for inp in inputs[:5]:
                        try:
                            inp_type = inp.get_attribute('type')
                            inp_name = inp.get_attribute('name')
                            
                            if inp_type == 'text' or inp_name in ['username', 'user', 'account']:
                                inp.fill('admin')
                            elif inp_type == 'password':
                                inp.fill('admin123')
                        except:
                            pass
                    
                    buttons = page.query_selector_all('button')
                    for btn in buttons[:5]:
                        try:
                            btn.click()
                            page.wait_for_timeout(300)
                        except:
                            pass
                    
                    page.wait_for_timeout(1000)
                except:
                    pass
            
            # 采集localStorage
            try:
                ls = page.evaluate("""
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
                cookies = context.cookies()
                result['storage']['cookies'] = [
                    {'name': c['name'], 'value': c['value'][:50]} 
                    for c in cookies
                ]
            except:
                pass
            
            # 采集表单
            try:
                forms = page.evaluate("""
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
                result['page_title'] = page.title()
            except:
                pass
            
            # 采集API请求
            result['apis'] = captured_apis
            
            browser.close()
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def extract_apis_from_browser(result):
    """从浏览器采集结果中提取API"""
    apis = result.get('apis', [])
    
    # 去重
    unique_apis = {}
    for api in apis:
        api_url = api['url']
        if api_url not in unique_apis:
            unique_apis[api_url] = api
    
    return list(unique_apis.values())


def extract_js_api_patterns(js_content):
    """
    从JS内容中提取API端点模式和配置
    
    返回:
        base_url: string - 发现的baseURL配置
        api_paths: Array<string> - 发现的API路径
        env_vars: object - 发现的环境变量
    """
    base_url = None
    api_paths = set()
    env_vars = {}
    
    # baseURL配置
    baseurl_patterns = [
        r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
        r'axios\.create\s*\(\s*\{[^}]*baseURL\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    for pattern in baseurl_patterns:
        match = re.search(pattern, js_content)
        if match:
            base_url = match.group(1)
            break
    
    # API路径
    api_patterns = [
        r'["\'](/(?:user|auth|admin|login|logout|api|v\d|frame|hszh|table|dashboard|supplement|attach|code|module|file)[a-zA-Z0-9_/?=&-]*)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'\.get\(["\']([^"\']+)["\']',
        r'\.post\(["\']([^"\']+)["\']',
    ]
    for pattern in api_patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for m in matches:
            if isinstance(m, str) and len(m) > 2 and len(m) < 200:
                api_paths.add(m)
    
    # 环境变量
    env_patterns = [
        r'(VUE_APP_\w+)\s*[:=]\s*["\']([^"\']+)["\']',
        r'process\.env\.(\w+)\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    for pattern in env_patterns:
        matches = re.findall(pattern, js_content)
        for var_name, var_value in matches:
            env_vars[var_name] = var_value
    
    return {
        'base_url': base_url,
        'api_paths': list(api_paths),
        'env_vars': env_vars
    }


if __name__ == '__main__':
    # 测试
    result = browser_collect({
        'url': 'https://example.com',
        'wait_until': 'networkidle',
        'interact': True
    })
    print(f"APIs: {len(result.get('apis', []))}")
    print(f"JS Files: {len(result.get('js_files', []))}")
    print(f"Tech Stack: {result.get('tech_stack', [])}")
    print(f"Storage: {len(result.get('storage', {}))}")
