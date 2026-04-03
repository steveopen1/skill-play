"""
响应类型分析 - 识别响应是真实API还是WAF/路由/错误页
输入: {response, expected_type}
输出: {type, is_suspicious, suspicious_reasons, sensitive_fields, is_valid_json, parsed_json}
"""

import re
import json


def response_analyzer(config):
    """
    分析HTTP响应类型和内容
    
    输入:
        response: {
            status: number,
            headers: dict,
            body: string,
            content_type: string
        }
        expected_type?: "json" | "html" | "any"
    
    输出:
        type: "json" | "html" | "empty" | "redirect"
        is_suspicious: boolean
        suspicious_reasons: string[]
        sensitive_fields: string[]
        is_valid_json: boolean
        parsed_json?: object
    """
    response = config.get('response', {})
    expected_type = config.get('expected_type', 'any')
    
    status = response.get('status', 0)
    body = response.get('body', '')
    headers = response.get('headers', {})
    content_type = response.get('content_type', '') or headers.get('Content-Type', '')
    
    result = {
        'type': 'unknown',
        'is_suspicious': False,
        'suspicious_reasons': [],
        'sensitive_fields': [],
        'is_valid_json': False,
        'parsed_json': None
    }
    
    # 判断响应类型
    if status in [301, 302, 303, 307, 308]:
        result['type'] = 'redirect'
        result['is_suspicious'] = True
        result['suspicious_reasons'].append('redirect')
        return result
    
    body_lower = body.lower()
    body_len = len(body)
    
    # 检查是否是HTML
    is_html = (
        '<!doctype html>' in body_lower or
        '<html' in body_lower or
        'text/html' in content_type.lower()
    )
    
    # 检查是否包含DOCTYPE
    hasdoctype = '<!doctype' in body_lower
    
    # 检查是否是JSON
    is_json = False
    parsed_json = None
    
    if 'application/json' in content_type.lower():
        try:
            parsed_json = json.loads(body)
            is_json = True
            result['is_valid_json'] = True
            result['parsed_json'] = parsed_json
        except:
            pass
    
    # 也尝试直接解析body
    if not is_json and body.strip().startswith('{'):
        try:
            parsed_json = json.loads(body)
            is_json = True
            result['is_valid_json'] = True
            result['parsed_json'] = parsed_json
        except:
            pass
    
    # 分类响应类型
    if body_len < 50:
        result['type'] = 'empty'
        if status == 200:
            result['is_suspicious'] = True
            result['suspicious_reasons'].append('empty_response')
    elif is_html:
        result['type'] = 'html'
        # HTML可能是WAF、SPA路由或错误页
        if 'waf' in body_lower or '安全' in body_lower or '拦截' in body_lower:
            result['suspicious_reasons'].append('waf_block')
        if 'not found' in body_lower or '404' in body_lower:
            result['suspicious_reasons'].append('not_found')
        if hasdoctype and 'vue' in body_lower or 'react' in body_lower:
            result['suspicious_reasons'].append('spa_route')
    elif is_json:
        result['type'] = 'json'
    else:
        result['type'] = 'other'
    
    # 检查敏感字段
    sensitive_patterns = {
        'password': r'password["\']?\s*[:=]\s*["\']([^"\']+)',
        'token': r'(?:token|Token|TOKEN)["\']?\s*[:=]\s*["\']([^"\']{10,})',
        'secret': r'secret["\']?\s*[:=]\s*["\']([^"\']+)',
        'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)',
        'jwt': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
    }
    
    if parsed_json:
        body_str = json.dumps(parsed_json)
    else:
        body_str = body
    
    for field_name, pattern in sensitive_patterns.items():
        matches = re.findall(pattern, body_str, re.I)
        if matches:
            result['sensitive_fields'].append({
                'field': field_name,
                'count': len(matches),
                'preview': matches[0][:50] if matches else ''
            })
    
    # 判断是否可疑
    if 'waf_block' in result['suspicious_reasons']:
        result['is_suspicious'] = True
    if 'spa_route' in result['suspicious_reasons']:
        result['is_suspicious'] = True
    if result['type'] == 'html' and expected_type == 'json':
        result['is_suspicious'] = True
    
    return result


def compare_responses(baseline, test):
    """
    对比两个响应的差异
    
    输入:
        baseline: response - 正常响应
        test: response - 测试响应
    
    输出:
        identical: boolean
        differences: Array<{field, baseline_value, test_value, significance}>
    """
    differences = []
    
    # 比较状态码
    if baseline.get('status') != test.get('status'):
        differences.append({
            'field': 'status',
            'baseline_value': baseline.get('status'),
            'test_value': test.get('status'),
            'significance': 'high'
        })
    
    # 比较响应长度
    baseline_len = len(baseline.get('body', ''))
    test_len = len(test.get('body', ''))
    
    if baseline_len != test_len:
        diff_ratio = abs(baseline_len - test_len) / max(baseline_len, test_len)
        significance = 'high' if diff_ratio > 0.5 else 'low'
        differences.append({
            'field': 'body_length',
            'baseline_value': baseline_len,
            'test_value': test_len,
            'significance': significance
        })
    
    # 比较响应类型
    baseline_type = response_analyzer({'response': baseline}).get('type')
    test_type = response_analyzer({'response': test}).get('type')
    
    if baseline_type != test_type:
        differences.append({
            'field': 'response_type',
            'baseline_value': baseline_type,
            'test_value': test_type,
            'significance': 'high'
        })
    
    identical = len(differences) == 0
    
    return {
        'identical': identical,
        'differences': differences
    }


if __name__ == '__main__':
    # 测试
    result = response_analyzer({
        'response': {
            'status': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': '{"code": 200, "data": {"userId": 1}}'
        }
    })
    print(f"Type: {result['type']}, Suspicious: {result['is_suspicious']}")
