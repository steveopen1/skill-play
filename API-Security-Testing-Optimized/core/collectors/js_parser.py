"""
JS源码解析 - 从HTML/JS中提取API配置

【重要】使用多模式解析：
1. 正则模式：快速提取API路径、baseURL、凭证等
2. Agent模式：下载JS供Agent解析（用于混淆JS）

输入: {html, js_urls, base_url}
输出: {
    api_patterns: API路径,
    base_urls: baseURL配置,
    tokens: token,
    endpoints: 完整端点,
    sensitive_urls: 敏感URL,
    ip_addresses: IP地址,
    domains: 相关域名,
    credentials: 发现的凭证,
    js_for_agent: [JS文件路径列表，供Agent解析]
}
"""

import re
import requests
from urllib.parse import urljoin, urlparse

requests.packages.urllib3.disable_warnings()


def js_parser(config):
    """
    解析JS文件提取API配置（AST+正则双模式）
    
    输入:
        html: string - 页面HTML
        js_urls?: string[] - JS URL列表
        base_url: string - 基准URL
        use_ast?: boolean - 是否使用AST解析（默认True）
    
    输出:
        api_patterns: string[] - API路径
        base_urls: string[] - API Base URL
        tokens: string[] - 可能的token
        endpoints: string[] - 完整端点
        sensitive_urls: string[] - 敏感URL
        ip_addresses: string[] - IP地址
        domains: string[] - 相关域名
        credentials: object - 发现的凭证
    """
    html = config.get('html', '')
    js_urls = config.get('js_urls', [])
    base_url = config.get('base_url', '')
    use_ast = config.get('use_ast', True)
    
    result = {
        'api_patterns': [],
        'base_urls': [],
        'tokens': [],
        'endpoints': [],
        'sensitive_urls': [],
        'ip_addresses': [],
        'domains': [],
        'credentials': {}
    }
    
    # 从HTML中提取JS URL
    if not js_urls:
        js_urls = extract_js_urls(html)
    
    # 提取Base URL配置
    base_urls = extract_base_urls(html)
    result['base_urls'] = base_urls
    
    # 提取API路径模式
    api_patterns = extract_api_patterns(html)
    result['api_patterns'] = api_patterns
    
    # 从HTML中提取敏感URL和IP
    html_sensitive = extract_sensitive_from_string(html)
    result['sensitive_urls'].extend(html_sensitive.get('urls', []))
    result['ip_addresses'].extend(html_sensitive.get('ips', []))
    result['domains'].extend(html_sensitive.get('domains', []))
    
    # 分析JS文件
    for js_url in js_urls[:15]:  # 增加分析数量
        full_url = resolve_js_url(js_url, base_url)
        if not full_url:
            continue
        
        try:
            js_content = fetch_js_content(full_url)
            if not js_content:
                continue
            
            # 【新增】AST模式解析
            if use_ast:
                ast_result = extract_with_ast(js_content)
                if 'error' not in ast_result:
                    # 从AST字符串字面量中提取API
                    for literal in ast_result.get('string_literals', []):
                        if is_api_path(literal):
                            result['api_patterns'].append(literal)
                        # 提取URL
                        urls = extract_urls_from_string(literal)
                        result['sensitive_urls'].extend(urls)
                        # 提取IP
                        ips = extract_ip_from_string(literal)
                        result['ip_addresses'].extend(ips)
            
            # 正则模式提取API路径
            js_api_patterns = extract_api_patterns(js_content)
            result['api_patterns'].extend(js_api_patterns)
            
            # 提取Base URL
            js_base_urls = extract_base_urls(js_content)
            result['base_urls'].extend(js_base_urls)
            
            # 提取Token
            js_tokens = extract_tokens(js_content)
            result['tokens'].extend(js_tokens)
            
            # 【新增】提取敏感信息
            sensitive = extract_sensitive_from_string(js_content)
            result['sensitive_urls'].extend(sensitive.get('urls', []))
            result['ip_addresses'].extend(sensitive.get('ips', []))
            result['domains'].extend(sensitive.get('domains', []))
            if sensitive.get('credentials'):
                result['credentials'].update(sensitive['credentials'])
            
        except:
            pass
    
    # 去重
    result['api_patterns'] = list(set(result['api_patterns']))
    result['base_urls'] = list(set(result['base_urls']))
    result['tokens'] = list(set(result['tokens']))
    result['sensitive_urls'] = list(set(result['sensitive_urls']))
    result['ip_addresses'] = list(set(result['ip_addresses']))
    result['domains'] = list(set(result['domains']))
    
    # 生成完整端点
    for base in result['base_urls']:
        for pattern in result['api_patterns']:
            if pattern.startswith('/'):
                endpoint = base.rstrip('/') + pattern
            else:
                endpoint = base + '/' + pattern
            result['endpoints'].append(endpoint)
    
    result['endpoints'] = list(set(result['endpoints']))
    
    return result


def extract_with_ast(js_content):
    """
    使用AST（esprima）深度解析JS代码
    
    【重要】需要先安装esprima: pip install esprima
    
    返回:
        {
            string_literals: 所有字符串字面量,
            object_properties: 对象属性,
            function_calls: 函数调用,
            import_sources: import来源
        }
        
    依赖:
        pip install esprima
    """
    try:
        import esprima
    except ImportError:
        return {
            'error': 'esprima not installed. Run: pip install esprima',
            'fix_command': 'pip install esprima'
        }
    
    try:
        # 解析JS为AST（带位置信息）
        ast = esprima.parse(js_content, sourceType='script', range=True)
        
        result = {
            'string_literals': [],
            'object_properties': {},
            'function_calls': [],
            'import_sources': []
        }
        
        def traverse(node, depth=0):
            if depth > 30:  # 防止过深递归
                return
            
            if hasattr(node, 'type'):
                # 字符串字面量
                if node.type == 'Literal' and isinstance(node.value, str):
                    result['string_literals'].append(node.value)
                
                # 对象属性（键值对）
                elif node.type == 'Property':
                    key_node = getattr(node, 'key', None)
                    value_node = getattr(node, 'value', None)
                    if key_node and hasattr(key_node, 'value'):
                        key = key_node.value
                        value = getattr(value_node, 'value', None) if value_node else None
                        if value and isinstance(value, str):
                            result['object_properties'][key] = value
                
                # 函数调用
                elif node.type == 'CallExpression':
                    callee = getattr(node, 'callee', None)
                    if callee:
                        if hasattr(callee, 'name'):
                            result['function_calls'].append(callee.name)
                        elif hasattr(callee, 'value'):
                            result['function_calls'].append(callee.value)
                
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
        
    except Exception as e:
        return {
            'error': f'AST parse failed: {str(e)[:100]}',
            'fix_command': 'pip install --upgrade esprima'
        }
        return fallback_result


def extract_simplified(content):
    """
    【新增】简化的字符串提取（AST失败时的fallback）
    
    使用简单的正则避免复杂模式报错
    """
    result = {
        'string_literals': [],
        'api_paths': [],
        'error': 'fallback_mode'
    }
    
    # 简化：提取所有双引号字符串
    try:
        double_quoted = re.findall(r'"([^"]{3,150})"', content)
        result['string_literals'].extend(double_quoted)
    except:
        pass
    
    try:
        # 简化：提取所有单引号字符串
        single_quoted = re.findall(r"'([^']{3,150})'", content)
        result['string_literals'].extend(single_quoted)
    except:
        pass
    
    # 筛选API路径
    api_keywords = ['user', 'auth', 'login', 'logout', 'api', 'frame', 'admin', 'info', 'list', 'supplement', 'dashboard', 'module', 'code', 'attach', 'v1', 'v2', 'v3']
    for s in result['string_literals']:
        if any(k in s.lower() for k in api_keywords):
            if s.startswith('/') or 'axios' in s.lower() or 'fetch' in s.lower():
                result['api_paths'].append(s)
    
    return result


def extract_sensitive_from_string(content):
    """
    从字符串中提取敏感信息
    
    返回:
        {
            urls: 发现的URL,
            ips: 发现的IP,
            domains: 发现的域名,
            credentials: 发现的凭证
        }
    """
    result = {
        'urls': set(),
        'ips': set(),
        'domains': set(),
        'credentials': {}
    }
    
    # 提取HTTP/HTTPS URL
    urls = re.findall(r'https?://[^\s"\'<>]+', content)
    result['urls'].update(urls)
    
    # 提取域名
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            result['domains'].add(parsed.netloc)
    
    # 提取IPv4地址
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ips = re.findall(ipv4_pattern, content)
    result['ips'].update(ips)
    
    # 提取凭证
    credential_patterns = [
        (r'(?:api[_-]?key|API[_-]?KEY)\s*[:=]\s*["\']([^"\']+)["\']', 'api_key'),
        (r'(?:secret[_-]?key|SECRET[_-]?KEY)\s*[:=]\s*["\']([^"\']+)["\']', 'secret_key'),
        (r'(?:access[_-]?token|ACCESS[_-]?TOKEN)\s*[:=]\s*["\']([^"\']+)["\']', 'access_token'),
        (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']', 'password'),
        (r'Bearer\s+([a-zA-Z0-9\-_\.]+)', 'bearer_token'),
        (r'Basic\s+([a-zA-Z0-9\-_\.+]+=*)', 'basic_auth'),
    ]
    
    for pattern, cred_type in credential_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            if len(match) > 3 and 'undefined' not in match.lower():  # 过滤无效值
                result['credentials'][cred_type] = match
    
    return {
        'urls': list(result['urls']),
        'ips': list(result['ips']),
        'domains': list(result['domains']),
        'credentials': result['credentials']
    }


def extract_urls_from_string(content):
    """从字符串中提取URL"""
    urls = set()
    
    http_urls = re.findall(r'https?://[^\s"\'<>]+', content)
    urls.update(http_urls)
    
    return list(urls)


def extract_ip_from_string(content):
    """从字符串中提取IP地址"""
    ips = set()
    
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    matches = re.findall(ipv4_pattern, content)
    ips.update(matches)
    
    return list(ips)


def extract_js_urls(html):
    """从HTML中提取JS URL"""
    js_urls = []
    
    # script标签
    src_pattern = r'<script[^>]+src=["\']([^"\']+\.js)["\']'
    matches = re.findall(src_pattern, html, re.I)
    js_urls.extend(matches)
    
    # link标签 (可能包含JS)
    href_pattern = r'<link[^>]+href=["\']([^"\']+\.js)["\']'
    matches = re.findall(href_pattern, html, re.I)
    js_urls.extend(matches)
    
    return js_urls


def extract_base_urls(content):
    """提取Base URL配置"""
    base_urls = []
    
    patterns = [
        r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
        r'apiBase\s*[:=]\s*["\']([^"\']+)["\']',
        r'API_BASE\s*[:=]\s*["\']([^"\']+)["\']',
        r'VUE_APP_API\s*[:=]\s*["\']([^"\']+)["\']',
        r'REACT_APP_API\s*[:=]\s*["\']([^"\']+)["\']',
        r'NEXT_PUBLIC_API\s*[:=]\s*["\']([^"\']+)["\']',
        r'axios\.defaults\.baseURL\s*=\s*["\']([^"\']+)["\']',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, content)
        base_urls.extend(matches)
    
    return base_urls


def extract_api_patterns(content):
    """提取API路径模式"""
    api_patterns = []
    
    # RESTful API模式
    patterns = [
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/v\d+/[^"\']+)["\']',
        r'["\'](/api\.php/[^"\']+)["\']',
        r'url\s*[:=]\s*["\']([^"\']*api[^"\']*)["\']',
        r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
        r'path\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    
    # 【重要】业务模块API模式 - 覆盖更多场景
    business_patterns = [
        # 用户认证类
        r'["\'](/(?:user|auth|login|logout|oauth|supplement|userinfo)[a-zA-Z0-9_/?=&-]*)["\']',
        # 框架管理类
        r'["\'](/(?:frame|module|code|attach|file)[a-zA-Z0-9_/?=&-]*)["\']',
        # Dashboard/统计类
        r'["\'](/(?:dashboard|table|dash|board|stats|statistics)[a-zA-Z0-9_/?=&-]*)["\']',
        # 微信相关
        r'["\'](/(?:wx|wechat|wxapi|hszh)[a-zA-Z0-9_/?=&-]*)["\']',
        # axios/fetch调用
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'\.get\(["\']([^"\']+)["\']',
        r'\.post\(["\']([^"\']+)["\']',
        r'\.put\(["\']([^"\']+)["\']',
        r'\.delete\(["\']([^"\']+)["\']',
    ]
    
    for pattern in patterns + business_patterns:
        matches = re.findall(pattern, content, re.I)
        for match in matches:
            if isinstance(match, str):
                api_patterns.append(match)
    
    # 过滤掉非API路径
    filtered = []
    for pattern in api_patterns:
        if is_api_path(pattern):
            filtered.append(pattern)
    
    return filtered


def extract_tokens(content):
    """提取可能的Token"""
    tokens = []
    
    patterns = [
        r'(?:token|Token|TOKEN)\s*[:=]\s*["\']([a-zA-Z0-9\-_\.]+)["\']',
        r'Bearer\s+([a-zA-Z0-9\-_\.]+)',
        r'Authorization["\']?\s*[:=]\s*["\'][^"\']*([a-zA-Z0-9\-_\.]+)',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, content, re.I)
        tokens.extend(matches)
    
    # 过滤掉测试token
    filtered = []
    for token in tokens:
        if len(token) > 10 and 'test' not in token.lower():
            filtered.append(token)
    
    return filtered


def is_api_path(path):
    """判断是否是API路径"""
    if not path or len(path) < 2:
        return False
    
    api_indicators = [
        '/api/', '/v1/', '/v2/', '/v3/', '/rest/',
        '/user', '/auth', '/login', '/logout', '/oauth',
        '/frame', '/module', '/code', '/attach', '/file',
        '/dashboard', '/table', '/supplement',
        '/wx', '/wechat', '/hszh', '/api',
    ]
    
    # 检查是否包含API指示符
    for indicator in api_indicators:
        if indicator in path.lower():
            return True
    
    # 过滤掉明显不是API的路径
    non_api_patterns = [
        '.css', '.js', '.html', '.png', '.jpg', '.gif',
        '/static/', '/public/', '/assets/', '/images/',
        'chunk-', 'app.', 'vendor.',
    ]
    for pattern in non_api_patterns:
        if pattern in path:
            return False
    
    return False


def resolve_js_url(js_url, base_url):
    """解析JS URL为完整URL"""
    if not js_url:
        return None
    
    if js_url.startswith('http'):
        return js_url
    
    if js_url.startswith('//'):
        parsed = urlparse(base_url)
        return f"{parsed.scheme}:{js_url}"
    
    if js_url.startswith('/'):
        parsed = urlparse(base_url)
        return f"{parsed.scheme}://{parsed.netloc}{js_url}"
    
    return urljoin(base_url, js_url)


def fetch_js_content(js_url):
    """获取JS文件内容"""
    try:
        resp = requests.get(js_url, timeout=10, verify=False)
        if resp.status_code == 200:
            return resp.text
    except:
        pass
    return None


if __name__ == '__main__':
    # 测试
    result = js_parser({
        'html': '<script src="/static/js/app.js"></script>',
        'base_url': 'https://example.com'
    })
    print(f"API Patterns: {result['api_patterns']}")
    print(f"Base URLs: {result['base_urls']}")


def prepare_js_for_agent_analysis(js_url, base_url):
    """
    【新增】下载JS文件，准备供Agent解析
    
    用于混淆JS无法用esprima解析时，将JS内容提供给Agent/LLM进行解析
    
    输入:
        js_url: string - JS文件URL
        base_url: string - 基准URL
    
    输出:
        {
            js_url: JS文件路径,
            js_content: JS原始内容（截断到20KB）,
            content_hash: 内容哈希,
            lines: 行数,
            prompt_template: Agent解析提示模板
        }
    """
    full_url = resolve_js_url(js_url, base_url) if not js_url.startswith('http') else js_url
    
    js_content = fetch_js_content(full_url)
    
    if not js_content:
        return {
            'error': f'Failed to fetch JS: {js_url}',
            'js_url': js_url
        }
    
    # 截断过长的JS（保留前20KB）
    truncated = len(js_content) > 20000
    display_content = js_content[:20000] if truncated else js_content
    
    prompt_template = f"""请分析以下JavaScript代码，提取API接口：

1. baseURL/basePath配置
2. 所有API路径（如 /user/login, /api/v1/user/info）
3. 请求方法（GET/POST/PUT/DELETE）
4. 参数名和参数位置（query/path/body）
5. 敏感信息（token、apiKey、硬编码凭证）
6. 外部URL或域名
7. IP地址

--- JS文件 ---
{js_content[:5000]}...
（共 {len(js_content)} 字符，已截断）

请返回JSON格式：
{{
  "base_url": "发现的baseURL或空",
  "api_paths": ["路径1", "路径2"],
  "sensitive": ["敏感信息"],
  "external_urls": ["外部URL"],
  "ips": ["IP地址"]
}}"""
    
    return {
        'js_url': js_url,
        'full_url': full_url,
        'js_content': display_content,
        'js_content_full': js_content if not truncated else None,
        'content_hash': str(hash(js_content)),
        'lines': len(js_content.split('\n')),
        'truncated': truncated,
        'agent_prompt': prompt_template if truncated else None,
        'fetch_success': True
    }


def batch_prepare_js_for_agent(js_urls, base_url):
    """
    批量下载JS文件准备Agent分析
    
    输入:
        js_urls: string[] - JS文件URL列表
        base_url: string - 基准URL
    
    输出:
        prepared: object[] - 准备好的JS列表
    """
    prepared = []
    
    for js_url in js_urls[:5]:  # 限制数量
        result = prepare_js_for_agent_analysis(js_url, base_url)
        if 'error' not in result:
            prepared.append(result)
    
    return prepared
