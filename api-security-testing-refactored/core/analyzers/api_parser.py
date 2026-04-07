"""
API端点解析 - 解析API结构
输入: {apis, base_url}
输出: {endpoints, methods, parameters}
"""

import re
import json


def api_parser(config):
    """
    解析API端点
    
    输入:
        apis: Array<{method, url, post_data}> - API请求列表
        base_url?: string - 基准URL
    
    输出:
        endpoints: string[] - 端点路径
        methods: object - 每个端点的方法
        parameters: object - 发现的参数
    """
    apis = config.get('apis', [])
    base_url = config.get('base_url', '')
    
    result = {
        'endpoints': [],
        'methods': {},
        'parameters': {}
    }
    
    # 解析每个API
    for api in apis:
        url = api.get('url', '')
        method = api.get('method', 'GET')
        
        # 提取路径
        path = extract_path(url, base_url)
        if not path:
            continue
        
        # 添加端点
        if path not in result['endpoints']:
            result['endpoints'].append(path)
            result['methods'][path] = []
        
        # 添加方法
        if method not in result['methods'][path]:
            result['methods'][path].append(method)
        
        # 提取参数
        params = extract_params(url)
        if params:
            result['parameters'][path] = params
    
    return result


def extract_path(url, base_url=''):
    """从URL中提取API路径"""
    # 移除query string
    path = url.split('?')[0]
    
    # 如果有base_url，尝试提取相对路径
    if base_url:
        if base_url.startswith('http'):
            from urllib.parse import urlparse
            base_parsed = urlparse(base_url)
            base_netloc = base_parsed.netloc
            
            if base_netloc in path:
                # 提取base_netloc之后的部分
                idx = path.find(base_netloc)
                path = path[idx + len(base_netloc):]
    
    # 只保留API路径
    if '/api/' in path:
        idx = path.find('/api/')
        path = path[idx:]
    elif '/v' in path and '/v' in path:
        # /v1/, /v2/等
        match = re.search(r'/v\d+/\w+', path)
        if match:
            return match.group(0)
    
    return path


def extract_params(url):
    """从URL中提取参数"""
    params = {}
    
    if '?' not in url:
        return params
    
    query = url.split('?')[1]
    
    # 解析query string
    pairs = query.split('&')
    for pair in pairs:
        if '=' in pair:
            key, value = pair.split('=', 1)
            params[key] = value
        else:
            params[pair] = ''
    
    return params


def parse_swagger_json(swagger_content):
    """
    解析Swagger/OpenAPI JSON
    
    输入:
        swagger_content: string - Swagger JSON内容
    
    输出:
        endpoints: Array<{path, method, parameters}>
    """
    endpoints = []
    
    try:
        data = json.loads(swagger_content)
        
        # OpenAPI 3.x
        if 'paths' in data:
            paths = data['paths']
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        params = details.get('parameters', [])
                        endpoint = {
                            'path': path,
                            'method': method.upper(),
                            'parameters': [p.get('name') for p in params],
                            'summary': details.get('summary', '')
                        }
                        endpoints.append(endpoint)
        
        # Swagger 2.x
        elif 'swagger' in data and 'paths' in data:
            paths = data['paths']
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        params = details.get('parameters', [])
                        endpoint = {
                            'path': path,
                            'method': method.upper(),
                            'parameters': [p.get('name') for p in params] if params else [],
                            'summary': details.get('summary', '')
                        }
                        endpoints.append(endpoint)
    
    except:
        pass
    
    return endpoints


def parse_postman_collection(collection_content):
    """
    解析Postman Collection
    
    输入:
        collection_content: string - Postman JSON内容
    
    输出:
        endpoints: Array<{name, method, url, body}>
    """
    endpoints = []
    
    try:
        data = json.loads(collection_content)
        
        items = data.get('item', [])
        
        for folder in items:
            if isinstance(folder, dict):
                name = folder.get('name', '')
                requests_list = folder.get('item', [])
                
                for req in requests_list:
                    if isinstance(req, dict):
                        endpoint = {
                            'name': req.get('name', name),
                            'method': req.get('request', {}).get('method', 'GET'),
                            'url': str(req.get('request', {}).get('url', '')),
                            'body': req.get('request', {}).get('body', {})
                        }
                        endpoints.append(endpoint)
    
    except:
        pass
    
    return endpoints


if __name__ == '__main__':
    # 测试
    result = api_parser({
        'apis': [
            {'method': 'GET', 'url': 'https://api.example.com/api/user/info?id=1'},
            {'method': 'POST', 'url': 'https://api.example.com/api/user/login'},
        ],
        'base_url': 'https://api.example.com'
    })
    print(f"Endpoints: {result['endpoints']}")
    print(f"Methods: {result['methods']}")
