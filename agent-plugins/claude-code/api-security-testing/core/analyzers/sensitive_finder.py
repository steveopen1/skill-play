"""
敏感信息发现 - 从响应/源码中提取敏感信息
输入: {content, check_fields}
输出: {found: [{field, value, position}], severity}
"""

import re
import json


def sensitive_finder(config):
    """
    发现敏感信息
    
    输入:
        content: string - 响应body或JS内容
        check_fields?: string[] - 自定义敏感字段
    
    输出:
        found: Array<{field, value, position}>
        severity: "high" | "medium" | "low"
    """
    content = str(content)
    check_fields = config.get('check_fields', [])
    
    # 默认敏感字段
    default_fields = [
        'password', 'passwd', 'pwd',
        'token', 'access_token', 'refresh_token',
        'secret', 'secret_key', 'app_secret',
        'api_key', 'apikey', 'api_secret',
        'private_key',
        'aws_access_key', 'aws_secret_key',
        'phone', 'mobile',
        'email',
        'id_card', 'idcard', '身份证',
        'balance', 'account', '余额'
    ]
    
    # 合并字段
    all_fields = set(default_fields + check_fields)
    
    found = []
    
    # 通用敏感信息模式
    patterns = {
        'password': [
            r'password["\']?\s*[:=]\s*["\']([^"\']{1,100})["\']',
            r'"pwd"\s*:\s*"([^"]+)"',
            r'"passwd"\s*:\s*"([^"]+)"',
        ],
        'token': [
            r'(?:token|Token|TOKEN)["\']?\s*[:=]\s*["\']([^"\']{10,200})["\']',
            r'Bearer\s+([a-zA-Z0-9\-_\.]+)',
        ],
        'jwt': [
            r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
        ],
        'phone': [
            r'1[3-9]\d{9}',
            r'\d{3}-?\d{4}-?\d{4}',
        ],
        'email': [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        ],
        'secret': [
            r'secret["\']?\s*[:=]\s*["\']([^"\']{1,100})["\']',
            r'appSecret["\']?\s*[:=]\s*["\']([^"\']{1,100})["\']',
        ],
        'api_key': [
            r'apiKey["\']?\s*[:=]\s*["\']([^"\']{1,100})["\']',
            r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{1,100})["\']',
        ],
        'aws_key': [
            r'AKIA[0-9A-Z]{16}',
        ],
        'private_key': [
            r'-----BEGIN[ A-Z]*PRIVATE KEY-----',
        ]
    }
    
    # 搜索敏感信息
    for field_name, field_patterns in patterns.items():
        for pattern in field_patterns:
            matches = re.finditer(pattern, content, re.I)
            for match in matches:
                value = match.group(0)
                # 过滤掉太长的值
                if len(value) > 200:
                    continue
                # 过滤掉测试数据
                if is_test_data(value):
                    continue
                found.append({
                    'field': field_name,
                    'value': value[:100],
                    'position': match.start()
                })
    
    # 搜索用户定义的字段
    for field in all_fields:
        if field.lower() in ['password', 'token', 'secret', 'api_key']:
            continue  # 已处理
        pattern = rf'{field}["\']?\s*[:=]\s*["\']([^"\']{{1,100}})["\']'
        matches = re.finditer(pattern, content, re.I)
        for match in matches:
            value = match.group(1)
            if len(value) > 100:
                continue
            if is_test_data(value):
                continue
            found.append({
                'field': field,
                'value': value[:50],
                'position': match.start()
            })
    
    # 判断严重性
    severity = 'low'
    high_severity = ['password', 'token', 'jwt', 'secret', 'api_key', 'aws_key', 'private_key']
    medium_severity = ['phone', 'email', 'id_card']
    
    found_fields = [f['field'].lower() for f in found]
    if any(f in found_fields for f in high_severity):
        severity = 'high'
    elif any(f in found_fields for f in medium_severity):
        severity = 'medium'
    
    return {
        'found': found,
        'severity': severity,
        'count': len(found)
    }


def is_test_data(value):
    """判断是否是测试数据"""
    test_patterns = [
        'test', 'TEST', 'Test',
        'xxx', 'xxx.xxx',
        'null', 'undefined',
        'example', 'sample',
        'placeholder'
    ]
    value_lower = value.lower()
    return any(t in value_lower for t in test_patterns)


def extract_secrets_from_json(data, path=''):
    """从JSON中递归提取敏感信息"""
    secrets = []
    
    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            
            sensitive_keys = ['password', 'token', 'secret', 'key', 'api', 'credential']
            if any(s in key.lower() for s in sensitive_keys):
                if isinstance(value, str) and len(value) > 0:
                    secrets.append({
                        'path': current_path,
                        'value': value[:50],
                        'key': key
                    })
            
            if isinstance(value, (dict, list)):
                secrets.extend(extract_secrets_from_json(value, current_path))
    
    elif isinstance(data, list):
        for i, item in enumerate(data):
            current_path = f"{path}[{i}]"
            if isinstance(item, (dict, list)):
                secrets.extend(extract_secrets_from_json(item, current_path))
    
    return secrets


if __name__ == '__main__':
    # 测试
    result = sensitive_finder({
        'content': '{"token": "eyJhbGciOiJIUzI1NiJ9", "password": "admin123"}',
        'check_fields': ['custom_field']
    })
    print(f"Found: {result['count']}, Severity: {result['severity']}")
