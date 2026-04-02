"""
JS源码解析 - 从HTML/JS中提取API配置
输入: {html, js_urls, base_url}
输出: {api_patterns, base_urls, tokens, endpoints}
"""

import re
import requests
from urllib.parse import urljoin, urlparse

requests.packages.urllib3.disable_warnings()


def js_parser(config):
    """
    解析JS文件提取API配置
    
    输入:
        html: string - 页面HTML
        js_urls?: string[] - JS URL列表
        base_url: string - 基准URL
    
    输出:
        api_patterns: string[] - API路径
        base_urls: string[] - API Base URL
        tokens: string[] - 可能的token
        endpoints: string[] - 完整端点
    """
    html = config.get('html', '')
    js_urls = config.get('js_urls', [])
    base_url = config.get('base_url', '')
    
    result = {
        'api_patterns': [],
        'base_urls': [],
        'tokens': [],
        'endpoints': []
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
    
    # 分析JS文件
    for js_url in js_urls[:10]:  # 限制数量
        full_url = resolve_js_url(js_url, base_url)
        if not full_url:
            continue
        
        try:
            js_content = fetch_js_content(full_url)
            if not js_content:
                continue
            
            # 提取API路径
            js_api_patterns = extract_api_patterns(js_content)
            result['api_patterns'].extend(js_api_patterns)
            
            # 提取Base URL
            js_base_urls = extract_base_urls(js_content)
            result['base_urls'].extend(js_base_urls)
            
            # 提取Token
            js_tokens = extract_tokens(js_content)
            result['tokens'].extend(js_tokens)
            
        except:
            pass
    
    # 去重
    result['api_patterns'] = list(set(result['api_patterns']))
    result['base_urls'] = list(set(result['base_urls']))
    result['tokens'] = list(set(result['tokens']))
    
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
