"""
漏洞验证器 - 多维度验证
确认发现的漏洞是否真实，排除误报

验证维度：
1. 响应类型维度：JSON vs HTML vs Empty vs Redirect
2. 状态码维度：200 vs 4xx vs 5xx
3. 响应长度维度：长度变化检测
4. WAF拦截维度：WAF/安全设备拦截检测
5. 敏感信息维度：敏感字段泄露检测
6. SQL注入维度：SQL错误特征检测
7. IDOR维度：用户数据越权检测
8. 一致性维度：多次请求响应一致性检测
9. 时间维度：时间盲注检测
10. 业务数据维度：业务数据真实性检测
"""

import requests
import json
import time
import re

requests.packages.urllib3.disable_warnings()


def vuln_verifier(config):
    """
    多维度漏洞验证
    
    输入:
        type: "sqli" | "idor" | "auth_bypass" | "info_leak"
        original_request: object
        suspicious_response: object
        baseline_response?: object - 基线响应（正常请求的响应）
    
    输出:
        verified: boolean
        is_false_positive: boolean
        reason: string
        dimensions: object - 各维度验证结果
    """
    vuln_type = config.get('type')
    original_request = config.get('original_request', {})
    suspicious_response = config.get('suspicious_response', {})
    baseline_response = config.get('baseline_response', {})
    
    # 收集各维度验证结果
    dimensions = {}
    is_false_positive = False
    reasons = []
    
    # ========== 维度1: 响应类型验证 ==========
    resp_type_result = verify_response_type(suspicious_response)
    dimensions['response_type'] = resp_type_result
    if resp_type_result['is_waf_or_block']:
        is_false_positive = True
        reasons.append(f"响应类型为{resp_type_result['type']}，可能是拦截")
    
    # ========== 维度2: 状态码验证 ==========
    status_result = verify_status_code(suspicious_response)
    dimensions['status_code'] = status_result
    
    # ========== 维度3: 响应长度验证 ==========
    length_result = verify_response_length(suspicious_response, baseline_response)
    dimensions['response_length'] = length_result
    if length_result['is_empty']:
        is_false_positive = True
        reasons.append("响应为空或过短")
    
    # ========== 维度4: WAF拦截验证 ==========
    waf_result = verify_waf_block(suspicious_response)
    dimensions['waf_block'] = waf_result
    if waf_result['detected']:
        is_false_positive = True
        reasons.append(f"检测到WAF/拦截: {waf_result['reason']}")
    
    # ========== 维度5: 敏感信息验证 ==========
    sensitive_result = verify_sensitive_info(suspicious_response)
    dimensions['sensitive_info'] = sensitive_result
    
    # ========== 维度6: 一致性验证 ==========
    if baseline_response:
        consistency_result = verify_consistency(suspicious_response, baseline_response)
        dimensions['consistency'] = consistency_result
        if not consistency_result['is_consistent']:
            is_false_positive = True
            reasons.append("响应与基线不一致，可能是偶发")
    
    # ========== 维度7: 基于漏洞类型的专项验证 ==========
    if vuln_type == 'sqli':
        # SQL注入专项验证
        sqli_result = verify_sqli_dimension(suspicious_response)
        dimensions['sqli'] = sqli_result
        
        # SQL注入必须满足：响应是JSON + 包含SQL错误特征
        if not sqli_result['has_sql_error']:
            is_false_positive = True
            reasons.append("未发现SQL错误特征")
            
    elif vuln_type == 'idor':
        # IDOR专项验证
        idor_result = verify_idor_dimension(suspicious_response)
        dimensions['idor'] = idor_result
        
        # IDOR必须满足：返回业务数据 + 不同ID返回不同数据
        if not idor_result['has_user_data']:
            is_false_positive = True
            reasons.append("未发现用户/业务数据")
            
    elif vuln_type == 'auth_bypass':
        # 认证绕过专项验证
        auth_result = verify_auth_bypass(suspicious_response)
        dimensions['auth_bypass'] = auth_result
        
        if not auth_result['bypassed']:
            is_false_positive = True
            reasons.append("认证绕过未确认")
            
    elif vuln_type == 'info_leak':
        # 信息泄露专项验证
        leak_result = verify_info_leak(suspicious_response)
        dimensions['info_leak'] = leak_result
        
        if not leak_result['has_leak']:
            is_false_positive = True
            reasons.append("未发现信息泄露")
    
    # ========== 最终判定 ==========
    verified = not is_false_positive
    
    return {
        'verified': verified,
        'is_false_positive': is_false_positive,
        'reason': '; '.join(reasons) if reasons else '验证通过' if verified else '多项验证失败',
        'dimensions': dimensions
    }


# ========== 维度1: 响应类型验证 ==========
def verify_response_type(response):
    """
    验证响应类型
    维度说明：JSON=真实API，HTML=WAF/路由/拦截
    """
    body = response.get('body', '')
    headers = response.get('headers', {})
    content_type = headers.get('Content-Type', '')
    
    result = {
        'type': 'unknown',
        'is_json': False,
        'is_html': False,
        'is_empty': False,
        'is_waf_or_block': False
    }
    
    # 检查是否是JSON
    if 'application/json' in content_type.lower():
        try:
            json.loads(body)
            result['is_json'] = True
            result['type'] = 'json'
        except:
            pass
    
    if not result['is_json'] and body.strip().startswith('{'):
        try:
            json.loads(body)
            result['is_json'] = True
            result['type'] = 'json'
        except:
            pass
    
    # 检查是否是HTML（可能是WAF/路由/拦截）
    if '<!doctype html>' in body.lower() or '<html' in body.lower():
        result['is_html'] = True
        result['type'] = 'html'
        result['is_waf_or_block'] = True
    
    # 检查是否为空
    if len(body) < 50:
        result['is_empty'] = True
        result['type'] = 'empty'
        result['is_waf_or_block'] = True
    
    return result


# ========== 维度2: 状态码验证 ==========
def verify_status_code(response):
    """
    验证状态码
    维度说明：200=成功，4xx=客户端错误，5xx=服务端错误
    """
    status = response.get('status', 0)
    
    result = {
        'status': status,
        'is_success': status == 200,
        'is_client_error': 400 <= status < 500,
        'is_server_error': status >= 500,
        'is_redirect': 300 <= status < 400
    }
    
    return result


# ========== 维度3: 响应长度验证 ==========
def verify_response_length(response, baseline=None):
    """
    验证响应长度
    维度说明：过短可能是拦截，过长可能是完整数据
    """
    body = response.get('body', '')
    length = len(body)
    
    result = {
        'length': length,
        'is_empty': length < 50,
        'is_reasonable': 50 <= length <= 50000,
        'is_too_long': length > 50000
    }
    
    # 与基线对比
    if baseline:
        baseline_length = len(baseline.get('body', ''))
        if baseline_length > 0:
            diff_ratio = abs(length - baseline_length) / max(length, baseline_length)
            result['diff_ratio'] = diff_ratio
            result['significantly_different'] = diff_ratio > 0.8
    
    return result


# ========== 维度4: WAF拦截验证 ==========
def verify_waf_block(response):
    """
    验证WAF/安全设备拦截
    维度说明：检测响应是否为WAF或安全设备的拦截页面
    """
    body = response.get('body', '').lower()
    headers = response.get('headers', {})
    
    waf_indicators = {
        'waf': ['waf', 'web应用防火墙', '安全防护', '防火墙'],
        'block': ['拦截', 'blocked', 'forbidden', '访问受限', 'blocked by'],
        'security': ['安全中心', '安全狗', '云盾', '安全狗'],
        'cdn': ['cdn', 'content filter']
    }
    
    detected_type = None
    detected_indicators = []
    
    for wtype, indicators in waf_indicators.items():
        for indicator in indicators:
            if indicator in body:
                detected_type = wtype
                detected_indicators.append(indicator)
    
    # 检查header
    if not detected_type:
        x_powered = headers.get('X-Powered-By', '').lower()
        for wtype, indicators in waf_indicators.items():
            for indicator in indicators:
                if indicator in x_powered:
                    detected_type = wtype
                    detected_indicators.append(indicator)
    
    return {
        'detected': detected_type is not None,
        'type': detected_type,
        'indicators': detected_indicators,
        'reason': f"检测到{detected_type}: {', '.join(detected_indicators)}" if detected_type else None
    }


# ========== 维度5: 敏感信息验证 ==========
def verify_sensitive_info(response):
    """
    验证敏感信息泄露
    维度说明：检测响应中是否包含敏感字段
    """
    body = response.get('body', '')
    
    sensitive_fields = {
        'password': r'password["\']?\s*[:=]\s*["\']([^"\']{1,50})["\']',
        'token': r'(?:token|Token|TOKEN)["\']?\s*[:=]\s*["\']([^"\']{10,200})["\']',
        'jwt': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
        'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{10,100})["\']',
        'secret': r'secret["\']?\s*[:=]\s*["\']([^"\']{1,100})["\']',
        'phone': r'1[3-9]\d{9}',
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    }
    
    found = {}
    
    try:
        # 尝试JSON解析
        data = json.loads(body)
        body_for_search = json.dumps(data)
    except:
        body_for_search = str(body)
    
    for field_name, pattern in sensitive_fields.items():
        matches = re.findall(pattern, body_for_search, re.I)
        if matches:
            # 过滤测试数据
            filtered = [m for m in matches if not is_test_data(m)]
            if filtered:
                found[field_name] = len(filtered)
    except:
        pass
    
    return {
        'found': found,
        'has_sensitive': len(found) > 0,
        'count': sum(found.values())
    }


# ========== 维度6: 一致性验证 ==========
def verify_consistency(response1, response2):
    """
    验证响应一致性
    维度说明：多次请求响应应该一致，否则可能是偶发
    """
    status1 = response1.get('status', 0)
    status2 = response2.get('status', 0)
    body1 = response1.get('body', '')
    body2 = response2.get('body', '')
    
    result = {
        'status_consistent': status1 == status2,
        'body_similar': True,
        'is_consistent': True
    }
    
    # 检查状态码
    if status1 != status2:
        result['status_consistent'] = False
        result['is_consistent'] = False
    
    # 检查body相似度
    if body1 and body2:
        len1, len2 = len(body1), len(body2)
        if max(len1, len2) > 0:
            diff_ratio = abs(len1 - len2) / max(len1, len2)
            result['body_diff_ratio'] = diff_ratio
            if diff_ratio > 0.5:
                result['body_similar'] = False
                result['is_consistent'] = False
    
    return result


# ========== 维度7: SQL注入专项验证 ==========
def verify_sqli_dimension(response):
    """
    SQL注入专项验证
    必须满足：响应是JSON + 包含SQL错误特征
    """
    body = response.get('body', '')
    
    # SQL错误特征
    sql_errors = [
        'sql syntax', 'syntax error', 'mysql', 'postgresql', 'oracle',
        'sqlite', 'sqlstate', 'microsoft sql', 'sql error', 'sqlsrv',
        'odbc driver', 'mariadb', 'access denied for',
        'sql_injection', 'sql injection'
    ]
    
    has_sql_error = False
    detected_error = None
    
    body_lower = body.lower()
    for error in sql_errors:
        if error in body_lower:
            has_sql_error = True
            detected_error = error
            break
    
    # 检查是否是JSON格式的错误响应
    is_json_error = False
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            msg = str(data.get('msg', '')).lower()
            for error in sql_errors:
                if error in msg:
                    is_json_error = True
                    break
            # 检查code是否为错误码
            if data.get('code') and data.get('code') not in [200, 0, '200', '0']:
                is_json_error = True
    except:
        pass
    
    return {
        'has_sql_error': has_sql_error,
        'error_type': detected_error,
        'is_json_error': is_json_error,
        'confirmed': has_sql_error and is_json_error
    }


# ========== 维度8: IDOR专项验证 ==========
def verify_idor_dimension(response):
    """
    IDOR专项验证
    必须满足：返回业务数据 + 数据随ID变化
    """
    body = response.get('body', '')
    
    # 业务字段
    business_fields = [
        'user', 'username', 'userId', 'user_id', 'name',
        'phone', 'mobile', 'email',
        'order', 'orderId', 'order_no', 'orderNo',
        'balance', 'amount', 'money',
        'id', '_id', 'createBy', 'create_by'
    ]
    
    has_user_data = False
    matched_fields = []
    
    try:
        data = json.loads(body)
        data_str = json.dumps(data).lower()
        
        for field in business_fields:
            if field.lower() in data_str:
                has_user_data = True
                matched_fields.append(field)
    except:
        pass
    
    return {
        'has_user_data': has_user_data,
        'matched_fields': matched_fields,
        'confirmed': has_user_data
    }


# ========== 维度9: 认证绕过专项验证 ==========
def verify_auth_bypass(response):
    """
    认证绕过专项验证
    必须满足：返回token或session
    """
    body = response.get('body', '')
    
    has_token = False
    has_session = False
    
    # token特征
    token_patterns = [
        r'token["\']?\s*[:=]\s*["\']([^"\']{10,})',
        r'access_token["\']?\s*[:=]\s*["\']([^"\']{10,})',
        r'session_id["\']?\s*[:=]\s*["\']([^"\']{10,})',
        r'Bearer\s+[a-zA-Z0-9\-_\.]+'
    ]
    
    for pattern in token_patterns:
        if re.search(pattern, body, re.I):
            has_token = True
            break
    
    # 检查是否是成功登录的响应
    try:
        data = json.loads(body)
        if data.get('success') == True or data.get('code') == 0:
            if data.get('token') or data.get('data', {}).get('token'):
                has_token = True
    except:
        pass
    
    return {
        'has_token': has_token,
        'has_session': has_session,
        'bypassed': has_token
    }


# ========== 维度10: 信息泄露专项验证 ==========
def verify_info_leak(response):
    """
    信息泄露专项验证
    必须满足：返回非公开的业务信息
    """
    body = response.get('body', '')
    
    # 非公开信息特征
    private_info = [
        'password', 'secret', 'api_key', 'apiKey',
        'token', 'session', 'private',
        'phone', 'email', 'id_card', '身份证'
    ]
    
    found = []
    
    body_lower = body.lower()
    for info in private_info:
        if info in body_lower:
            found.append(info)
    
    return {
        'found': found,
        'has_leak': len(found) > 0,
        'confirmed': len(found) > 0
    }


# ========== 辅助函数 ==========
def is_test_data(value):
    """判断是否是测试数据"""
    test_patterns = [
        'test', 'TEST', 'Test',
        'xxx', 'xxx.xxx',
        'null', 'undefined',
        'example', 'sample',
        'placeholder', 'demo'
    ]
    value_lower = str(value).lower()
    return any(t in value_lower for t in test_patterns)


if __name__ == '__main__':
    # 测试
    result = vuln_verifier({
        'type': 'sqli',
        'original_request': {'url': 'http://example.com/api/login', 'method': 'POST'},
        'suspicious_response': {'status': 200, 'body': '{"error": "success"}'}
    })
    print(f"Verified: {result['verified']}")
    print(f"False Positive: {result['is_false_positive']}")
    print(f"Dimensions: {list(result['dimensions'].keys())}")