"""
无头浏览器采集 - 使用Playwright进行动态采集
输入: {url, wait_until, interact, intercept_api}
输出: {apis, storage, forms, page_title, js_files, tech_stack, sensitive_urls, ip_addresses}

【重要】SPA采集完整流程：
1. browser_collect 采集JS文件、API请求、外部URL、IP
2. js_parser 分析JS提取API端点和baseURL配置
3. sensitive_finder 提取敏感信息
4. http_client 测试发现的API
"""

import asyncio
import re
import json
import requests
from urllib.parse import urlparse, parse_qs

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

requests.packages.urllib3.disable_warnings()


def browser_collect(config):
    """
    使用无头浏览器采集API和信息（同步版本）
    
    输入:
        url: string - 目标URL
        wait_until?: "networkidle" | "domcontentloaded"
        interact?: boolean - 是否模拟交互
        intercept_api?: boolean - 是否拦截API请求
        extract_js_files?: boolean - 是否提取JS文件列表
        extract_external_urls?: boolean - 是否提取外部URL/域名
        extract_ip_addresses?: boolean - 是否提取IP地址
    
    输出:
        apis: Array<{method, url, post_data}>
        storage: {localStorage, cookies}
        forms: Array<{action, method, inputs}>
        page_title: string
        js_files: Array<string> - JS文件路径列表
        tech_stack: Array<string> - 检测到的技术栈
        sensitive_urls: Array<string> - 发现的敏感URL（API、后台等）
        ip_addresses: Array<string> - 发现的IP地址
        domains: Array<string> - 发现的相关域名
    """
    if not PLAYWRIGHT_AVAILABLE:
        return {
            'error': 'playwright_not_available',
            'apis': [],
            'storage': {},
            'forms': [],
            'js_files': [],
            'tech_stack': [],
            'sensitive_urls': [],
            'ip_addresses': [],
            'domains': []
        }
    
    url = config.get('url')
    wait_until = config.get('wait_until', 'networkidle')
    interact = config.get('interact', False)
    intercept_api = config.get('intercept_api', True)
    extract_js_files = config.get('extract_js_files', True)
    extract_external_urls = config.get('extract_external_urls', True)
    extract_ip_addresses = config.get('extract_ip_addresses', True)
    
    result = {
        'apis': [],
        'storage': {},
        'forms': [],
        'page_title': '',
        'js_files': [],
        'tech_stack': [],
        'sensitive_urls': [],
        'ip_addresses': [],
        'domains': []
    }
    
    target_domain = urlparse(url).netloc
    
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
            captured_urls = []  # 所有请求的完整URL
            all_responses = []  # 所有响应
            
            if intercept_api:
                def on_request(request):
                    if request.resource_type in ['xhr', 'fetch', 'document', 'script']:
                        captured_apis.append({
                            'method': request.method,
                            'url': request.url,
                            'post_data': request.post_data,
                            'headers': dict(request.headers)
                        })
                        captured_urls.append(request.url)
                
                def on_response(response):
                    all_responses.append({
                        'url': response.url,
                        'status': response.status,
                        'headers': dict(response.headers),
                        'content_type': response.headers.get('content-type', '')
                    })
                
                page.on('request', on_request)
                page.on('response', on_response)
            
            # 访问页面
            try:
                response = page.goto(url, timeout=60000, wait_until=wait_until)
                result['status_code'] = response.status if response else None
                result['response_headers'] = dict(response.headers) if response else {}
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
                    
                    # 【新增】从HTML中提取敏感URL
                    html_urls = extract_urls_from_html(html_content, target_domain)
                    result['sensitive_urls'].extend(html_urls)
                    
                except Exception as e:
                    result['js_extract_error'] = str(e)
            
            # 【新增】提取外部URL和IP
            if extract_external_urls or extract_ip_addresses:
                all_urls = set()
                all_ips = set()
                all_domains = set()
                
                # 从请求中提取
                for req_url in captured_urls:
                    parsed = urlparse(req_url)
                    
                    # 收集域名
                    if parsed.netloc and parsed.netloc != target_domain:
                        all_domains.add(parsed.netloc)
                    
                    # 收集完整URL
                    all_urls.add(req_url)
                    
                    # 提取IP
                    if extract_ip_addresses:
                        ips = extract_ip_addresses_from_string(req_url)
                        all_ips.update(ips)
                
                # 从响应头中提取
                for resp in all_responses:
                    headers_str = json.dumps(resp.get('headers', {}))
                    
                    if extract_external_urls:
                        # 从header中提取URL
                        url_in_headers = re.findall(r'https?://[^\s"\'<>]+', headers_str)
                        all_urls.update(url_in_headers)
                        
                        # 提取域名
                        for u in url_in_headers:
                            p = urlparse(u)
                            if p.netloc:
                                all_domains.add(p.netloc)
                    
                    if extract_ip_addresses:
                        ips = extract_ip_addresses_from_string(headers_str)
                        all_ips.update(ips)
                
                result['sensitive_urls'] = list(all_urls)
                result['ip_addresses'] = list(all_ips)
                result['domains'] = list(all_domains)
            
            # 模拟交互（增强版：自动尝试登录触发API）
            if interact:
                try:
                    # 1. 查找登录表单
                    inputs = page.query_selector_all('input')
                    for inp in inputs[:10]:
                        try:
                            inp_type = inp.get_attribute('type')
                            inp_name = inp.get_attribute('name')
                            inp_id = inp.get_attribute('id')
                            
                            # 填写用户名
                            if inp_type == 'text' or inp_name in ['username', 'user', 'account', 'uname'] or inp_id in ['username', 'user']:
                                inp.fill('admin')
                            # 填写密码
                            elif inp_type == 'password':
                                inp.fill('admin123')
                        except:
                            pass
                    
                    # 2. 查找登录按钮并点击
                    buttons = page.query_selector_all('button')
                    for btn in buttons[:5]:
                        try:
                            btn_text = btn.inner_text()
                            if any(k in btn_text.lower() for k in ['login', '登录', 'submit', '确定']):
                                btn.click()
                                page.wait_for_timeout(2000)  # 等待登录请求
                                break
                        except:
                            pass
                    
                    # 3. 如果有form直接提交
                    try:
                        page.evaluate("""
                            () => {
                                const forms = document.querySelectorAll('form');
                                forms.forEach(f => {
                                    if (f.querySelector('input[type="password"]')) {
                                        f.submit();
                                    }
                                });
                            }
                        """)
                        page.wait_for_timeout(2000)
                    except:
                        pass
                    
                    # 4. 捕获登录后的API请求
                    page.wait_for_timeout(3000)
                    
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
                
                # 【新增】从localStorage中提取敏感信息
                if ls:
                    for key, value in ls.items():
                        if any(k in key.lower() for k in ['token', 'key', 'secret', 'auth']):
                            result['sensitive_urls'].append(f"localStorage:{key}")
                        # 提取URL
                        urls = extract_urls_from_string(str(value))
                        result['sensitive_urls'].extend(urls)
                        # 提取IP
                        ips = extract_ip_addresses_from_string(str(value))
                        result['ip_addresses'].extend(ips)
                        
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
            
            # 【新增】登录即测：发现login请求时立即分析
            login_test = analyze_login_requests(captured_apis, url)
            if login_test:
                result['login_test_hint'] = login_test
            
            browser.close()
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def analyze_login_requests(captured_apis, target_url):
    """
    【新增】分析捕获到的登录请求，返回测试提示
    
    发现login请求时，返回测试建议
    """
    login_keywords = ['login', 'signin', 'auth', 'token', 'pwd', 'password']
    
    for api in captured_apis:
        url = api.get('url', '')
        method = api.get('method', 'GET')
        post_data = api.get('post_data', '')
        
        # 检查是否是登录相关请求
        is_login = any(k in url.lower() for k in login_keywords)
        if post_data and any(k in str(post_data).lower() for k in login_keywords):
            is_login = True
        
        if is_login:
            # 构建测试提示
            test_hints = []
            
            # GET请求
            if method == 'GET' and 'password' in url:
                test_hints.append({
                    'type': 'GET_login_with_password_in_url',
                    'url': url,
                    'risk': 'HIGH',
                    'description': '密码可能暴露在URL中'
                })
            
            # POST请求
            if method == 'POST' and post_data:
                test_hints.append({
                    'type': 'POST_login_test',
                    'url': url,
                    'method': 'POST',
                    'body': post_data,
                    'risk': 'MEDIUM',
                    'description': '立即测试SQL注入、弱密码'
                })
                
                # SQL注入测试payload
                sql_payloads = [
                    {"username": "admin'--", "password": "any"},
                    {"username": "admin' OR '1'='1", "password": "any"},
                ]
                test_hints[0]['sql_payloads'] = sql_payloads
            
            return {
                'found_login': True,
                'url': url,
                'method': method,
                'test_hints': test_hints
            }
    
    return None


def extract_urls_from_html(html_content, target_domain):
    """从HTML内容中提取所有URL"""
    urls = set()
    
    # href属性
    hrefs = re.findall(r'href=["\']([^"\']+)["\']', html_content)
    for href in hrefs:
        if href.startswith('http'):
            parsed = urlparse(href)
            if parsed.netloc != target_domain:
                urls.add(href)
        elif href.startswith('/') or href.startswith('./'):
            urls.add(href)
    
    # src属性
    srcs = re.findall(r'src=["\']([^"\']+)["\']', html_content)
    for src in srcs:
        if src.startswith('http'):
            urls.add(src)
    
    # URL模板
    url_templates = re.findall(r'["\'](https?://[^"\']+)["\']', html_content)
    urls.update(url_templates)
    
    return list(urls)


def extract_urls_from_string(content):
    """从字符串中提取URL"""
    urls = set()
    
    # HTTP/HTTPS URL
    http_urls = re.findall(r'https?://[^\s"\'<>]+', content)
    urls.update(http_urls)
    
    return list(urls)


def extract_ip_addresses_from_string(content):
    """从字符串中提取IP地址"""
    ips = set()
    
    # IPv4地址
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ipv4_matches = re.findall(ipv4_pattern, content)
    ips.update(ipv4_matches)
    
    return list(ips)


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
    
    【使用AST+正则双模式】
    
    返回:
        base_url: string - 发现的baseURL配置
        api_paths: Array<string> - 发现的API路径
        env_vars: object - 发现的环境变量
        sensitive_urls: Array<string> - 发现的敏感URL
        ip_addresses: Array<string> - 发现的IP地址
    """
    base_url = None
    api_paths = set()
    env_vars = {}
    sensitive_urls = set()
    ip_addresses = set()
    
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
            # 检查环境变量中是否包含敏感URL或IP
            sensitive_urls.update(extract_urls_from_string(var_value))
            ip_addresses.update(extract_ip_addresses_from_string(var_value))
    
    # 【新增】从JS中提取敏感信息
    # 密钥/凭证模式
    credential_patterns = [
        r'["\']((?:api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key)["\']\s*[:=]\s*["\']([^"\']+)["\']',
        r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']',
        r'["\']https?://[^"\']*[:@][^"\']+@[^"\']+["\']',  # URL with credentials
    ]
    for pattern in credential_patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        sensitive_urls.update(matches)
    
    # 【新增】提取IP
    ip_addresses.update(extract_ip_addresses_from_string(js_content))
    
    # 【新增】提取外部URL
    sensitive_urls.update(extract_urls_from_string(js_content))
    
    return {
        'base_url': base_url,
        'api_paths': list(api_paths),
        'env_vars': env_vars,
        'sensitive_urls': list(sensitive_urls),
        'ip_addresses': list(ip_addresses)
    }


# 【新增】AST模式解析（使用esprima）
def extract_with_ast(js_content):
    """
    使用AST（esprima）深度解析JS代码
    
    需要先安装: pip install esprima
    
    返回:
        ast_info: dict - AST解析结果
    """
    try:
        import esprima
        
        # 解析JS为AST
        ast = esprima.parse(js_content, sourceType='script', range=True)
        
        result = {
            'string_literals': [],
            'object_properties': {},
            'function_calls': [],
            'import_sources': []
        }
        
        # 遍历AST提取信息
        def traverse(node, depth=0):
            if depth > 20:  # 防止过深递归
                return
                
            if hasattr(node, 'type'):
                # 字符串字面量
                if node.type == 'Literal' and isinstance(node.value, str):
                    result['string_literals'].append(node.value)
                
                # 对象属性
                elif node.type == 'Property':
                    key = getattr(node, 'key', None)
                    value = getattr(node, 'value', None)
                    if key and hasattr(key, 'value'):
                        result['object_properties'][key.value] = getattr(value, 'value', None)
                
                # 函数调用
                elif node.type == 'CallExpression':
                    callee = getattr(node, 'callee', None)
                    if callee and hasattr(callee, 'name'):
                        result['function_calls'].append(callee.name)
                
                # Import声明
                elif node.type == 'ImportDeclaration':
                    source = getattr(node, 'source', None)
                    if source and hasattr(source, 'value'):
                        result['import_sources'].append(source.value)
                
                # 递归遍历子节点
                for child in node.__dict__.values():
                    if isinstance(child, list):
                        for item in child:
                            if hasattr(item, 'type'):
                                traverse(item, depth + 1)
                    elif hasattr(child, 'type'):
                        traverse(child, depth + 1)
        
        traverse(ast.body)
        
        # 去重
        result['string_literals'] = list(set(result['string_literals']))
        result['function_calls'] = list(set(result['function_calls']))
        result['import_sources'] = list(set(result['import_sources']))
        
        return result
        
    except ImportError:
        return {'error': 'esprima not installed, use regex fallback'}
    except Exception as e:
        return {'error': str(e)}


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
    print(f"Sensitive URLs: {len(result.get('sensitive_urls', []))}")
    print(f"IP Addresses: {len(result.get('ip_addresses', []))}")
    print(f"Domains: {len(result.get('domains', []))}")
    print(f"Storage: {len(result.get('storage', {}))}")
