"""
HTTP请求能力 - 快速HTTP探测
输入: {url, method, headers, body, timeout}
输出: {status, headers, body, elapsed}
"""

import requests
import time

requests.packages.urllib3.disable_warnings()


def http_request(config):
    """
    发送HTTP请求
    
    输入:
        url: string - 目标URL
        method: string - HTTP方法 (GET, POST, PUT, DELETE, PATCH, OPTIONS)
        headers?: dict - 请求头
        body?: dict | string - 请求体
        files?: dict - 文件上传 (multipart/form-data)
        timeout?: number - 超时时间(秒)
    
    输出:
        status: number - HTTP状态码
        headers: dict - 响应头
        body: string - 响应体
        elapsed: number - 请求耗时(秒)
    """
    url = config.get('url')
    method = config.get('method', 'GET').upper()
    headers = config.get('headers', {})
    body = config.get('body')
    files = config.get('files')
    timeout = config.get('timeout', 10)
    
    start = time.time()
    
    try:
        if method == 'GET':
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False)
        elif method == 'POST':
            if files:
                resp = requests.post(url, files=files, headers=headers, timeout=timeout, verify=False)
            elif isinstance(body, dict):
                resp = requests.post(url, json=body, headers=headers, timeout=timeout, verify=False)
            else:
                resp = requests.post(url, data=body, headers=headers, timeout=timeout, verify=False)
        elif method == 'PUT':
            if files:
                resp = requests.put(url, files=files, headers=headers, timeout=timeout, verify=False)
            elif isinstance(body, dict):
                resp = requests.put(url, json=body, headers=headers, timeout=timeout, verify=False)
            else:
                resp = requests.put(url, data=body, headers=headers, timeout=timeout, verify=False)
        elif method == 'PATCH':
            if isinstance(body, dict):
                resp = requests.patch(url, json=body, headers=headers, timeout=timeout, verify=False)
            else:
                resp = requests.patch(url, data=body, headers=headers, timeout=timeout, verify=False)
        elif method == 'DELETE':
            resp = requests.delete(url, headers=headers, timeout=timeout, verify=False)
        elif method == 'OPTIONS':
            resp = requests.options(url, headers=headers, timeout=timeout, verify=False)
        else:
            resp = requests.request(method, url, headers=headers, timeout=timeout, verify=False)
        
        elapsed = time.time() - start
        
        return {
            'status': resp.status_code,
            'headers': dict(resp.headers),
            'body': resp.text,
            'elapsed': elapsed,
            'content_type': resp.headers.get('Content-Type', '')
        }
    except Exception as e:
        elapsed = time.time() - start
        return {
            'status': 0,
            'headers': {},
            'body': str(e),
            'elapsed': elapsed,
            'error': str(e)
        }


def check_health(url, timeout=5):
    """
    检查端点是否可达
    
    输入:
        url: string - 目标URL
        timeout?: number - 超时时间
    
    输出:
        healthy: boolean - 是否可达
        latency: number - 延迟(毫秒)
    """
    try:
        start = time.time()
        resp = requests.get(url, timeout=timeout, verify=False)
        latency = (time.time() - start) * 1000
        return {
            'healthy': resp.status_code < 500,
            'latency': latency,
            'status': resp.status_code
        }
    except:
        return {
            'healthy': False,
            'latency': 0,
            'status': 0
        }


if __name__ == '__main__':
    # 测试
    result = http_request({
        'url': 'https://httpbin.org/get',
        'method': 'GET'
    })
    print(f"Status: {result['status']}, Elapsed: {result['elapsed']:.2f}s")
