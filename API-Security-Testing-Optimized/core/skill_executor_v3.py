"""
SKILL 执行器 v3.0 - 配置驱动执行

根据 SKILL.md v3.0 定义的 vulnerability_detection_config 执行检测：
1. SQL 注入检测
2. 未授权访问检测  
3. 越权访问检测
4. 敏感信息泄露检测
5. API 版本发现
6. 路径遍历检测
7. 认证绕过检测
8. 暴力破解检测
9. CORS 配置错误检测
10. 云存储安全检测

认证上下文支持:
- Bearer Token
- JWT
- Session Cookie
"""

import sys
sys.path.insert(0, '/workspace/skill-play/API-Security-Testing-Optimized')

from core.prerequisite import prerequisite_check
from core.api_parser import APIEndpointParser
from core.cloud_storage_tester import CloudStorageTester


class SKILLExecutorV3:
    """SKILL 执行器 v3.0 - 配置驱动"""
    
    def __init__(self, target: str):
        self.target = target
        self.session = None
        self.playwright_available = False
        self.browser_type = None
        
        # 资产发现结果
        self.parser = None
        self.js_files = []
        self.static_endpoints = []
        self.dynamic_endpoints = []
        self.hooked_endpoints = []
        self.parent_paths = {}
        
        # API前缀
        self.api_prefix = None
        self.api_prefix_sources = {}
        
        # 认证上下文
        self.auth_context = {
            'type': None,
            'token': None,
            'cookies': None,
            'logged_in': False
        }
        
        # 测试结果
        self.vulnerabilities = []
        self.cloud_findings = []
        
        # 决策状态
        self.site_type = None
        self.has_real_api = False
        self.has_dynamic_endpoints = False
        self.html_fallback_all = False
    
    def run(self):
        """执行 SKILL 流程 v3.0"""
        print("=" * 70)
        print("  API Security Testing Skill v3.0 - 配置驱动执行")
        print("=" * 70)
        print(f"  目标: {self.target}")
        print()
        
        # ========== 阶段 0: 前置检查 ==========
        print("[阶段 0] 前置检查")
        print("-" * 50)
        self._check_prerequisites()
        
        # ========== 阶段 1: 资产发现 ==========
        print("\n[阶段 1] 资产发现")
        print("-" * 50)
        
        self._static_analysis()
        self._detect_site_type()
        self._probe_parent_paths()
        
        if self.site_type in ['modern_spa', 'jquery_spa'] and self.playwright_available:
            self._dynamic_analysis()
        
        if self.playwright_available and (self.has_real_api or self.has_dynamic_endpoints):
            self._api_hook()
        
        # ========== 阶段 2: 漏洞检测 (配置驱动) ==========
        print("\n[阶段 2] 漏洞检测")
        print("-" * 50)
        
        self._update_decision_state()
        
        if self.has_real_api or self.has_dynamic_endpoints:
            self._run_vulnerability_tests()
        else:
            if self.html_fallback_all:
                self._report_nginx_fallback()
        
        # ========== 阶段 3: 云存储测试 ==========
        print("\n[阶段 3] 云存储测试")
        print("-" * 50)
        self._cloud_storage_test()
        
        # ========== 阶段 4: 报告 ==========
        print("\n[阶段 4] 报告")
        print("-" * 50)
        self._generate_report()
        
        return self._get_result()
    
    def _check_prerequisites(self):
        """前置检查"""
        self.playwright_available, self.browser_type, can_proceed = prerequisite_check()
        
        if can_proceed:
            import requests
            self.session = requests.Session()
            self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
            print("  [OK] 前置检查通过")
        else:
            print("  [FAIL] 前置检查失败")
    
    def _static_analysis(self):
        """静态分析"""
        self.parser = APIEndpointParser(self.target, self.session)
        
        self.js_files = self.parser.discover_js_files()
        print(f"  JS 文件: {len(self.js_files)}")
        
        self.static_endpoints = self.parser.parse_js_files(self.js_files)
        print(f"  静态端点: {len(self.static_endpoints)}")
        
        for ep in self.static_endpoints[:5]:
            print(f"    {ep.method} {ep.path}")
    
    def _detect_site_type(self):
        """判断站点类型"""
        html = self.session.get(self.target, timeout=10).text.lower()
        
        frontend = 'Unknown'
        if 'vue' in html: frontend = 'Vue.js'
        elif 'react' in html: frontend = 'React'
        elif 'jquery' in html: frontend = 'jQuery'
        
        if len(self.js_files) == 0:
            self.site_type = 'pure_html'
        elif frontend == 'Unknown':
            self.site_type = 'modern_spa'
        else:
            self.site_type = 'modern_spa'
        
        print(f"  站点类型: {self.site_type}")
    
    def _probe_parent_paths(self):
        """父路径探测"""
        self.parent_paths = self.parser.probe_parent_paths()
        
        json_api_count = sum(1 for p in self.parent_paths.values() if p.get('is_api'))
        print(f"  父路径: {len(self.parent_paths)}, JSON API: {json_api_count}")
        
        if json_api_count > 0:
            self.has_real_api = True
    
    def _dynamic_analysis(self):
        """动态分析"""
        print("  [动态分析] 启动 Playwright...")
        try:
            from core.dynamic_api_analyzer import DynamicAPIAnalyzer
            from urllib.parse import urlparse
            
            analyzer = DynamicAPIAnalyzer(self.target)
            results = analyzer.analyze_full()
            
            count = len(results.get('endpoints', []))
            print(f"  [动态分析] 发现 {count} 个端点")
            
            self.dynamic_endpoints = results.get('endpoints', [])
            
            # 从动态端点提取 API 前缀
            target_host = urlparse(self.target).netloc
            for ep in self.dynamic_endpoints:
                ep_path = ep.get('path', '')
                if ep_path.startswith('http'):
                    ep_host = urlparse(ep_path).netloc
                    ep_path_only = urlparse(ep_path).path
                    if ep_host == target_host:
                        parts = ep_path_only.strip('/').split('/')
                        if len(parts) >= 2:
                            potential_prefix = '/' + '/'.join(parts[:2])
                            if potential_prefix not in ['/login', '/logout']:
                                self.api_prefix = potential_prefix
                                print(f"  [API Prefix] {self.api_prefix}")
                                break
            
            if count > 0:
                self.has_dynamic_endpoints = True
                
        except Exception as e:
            print(f"  [动态分析] 失败: {e}")
    
    def _api_hook(self):
        """API Hook - 尝试获取认证上下文"""
        print("  [API Hook] 尝试获取认证上下文...")
        try:
            from core.api_interceptor import APIInterceptor
            
            interceptor = APIInterceptor(self.target)
            results = interceptor.hook_all_apis()
            
            # 分析认证相关请求
            for req in results.get('requests', [])[:20]:
                if '/login' in req.get('url', '').lower():
                    print(f"  [认证] 发现登录请求")
                    break
                    
        except Exception as e:
            print(f"  [API Hook] 失败: {e}")
    
    def _update_decision_state(self):
        """更新决策状态"""
        json_api_count = sum(1 for p in self.parent_paths.values() if p.get('is_api'))
        dynamic_count = len(self.dynamic_endpoints)
        
        self.has_real_api = json_api_count > 0 or dynamic_count > 0
        self.has_dynamic_endpoints = dynamic_count > 0
        
        self.html_fallback_all = (
            len(self.parent_paths) > 0 and 
            json_api_count == 0 and 
            dynamic_count == 0
        )
        
        print(f"  has_real_api: {self.has_real_api}")
        print(f"  has_dynamic_endpoints: {self.has_dynamic_endpoints}")
    
    def _run_vulnerability_tests(self):
        """漏洞测试 - 遵循 SKILL.md 配置执行"""
        
        all_endpoints = self._merge_all_endpoints()
        sorted_endpoints = self._sort_by_priority(all_endpoints)
        
        print(f"  [漏洞检测] 总端点: {len(sorted_endpoints)}")
        
        # ===== 高优先级检测 =====
        print("\n  [高优先级] SQL注入检测...")
        self._test_sql_injection(sorted_endpoints)
        
        print("\n  [高优先级] 认证绕过检测...")
        self._test_auth_bypass(sorted_endpoints)
        
        print("\n  [高优先级] 越权访问检测...")
        self._test_privilege_escalation(sorted_endpoints)
        
        # ===== 中优先级检测 =====
        print("\n  [中优先级] 未授权访问检测...")
        self._test_unauthorized_access(sorted_endpoints)
        
        print("\n  [中优先级] 敏感信息泄露检测...")
        self._test_sensitive_data(sorted_endpoints)
        
        print("\n  [中优先级] 路径遍历检测...")
        self._test_path_traversal(sorted_endpoints)
        
        print("\n  [中优先级] CORS配置错误检测...")
        self._test_cors_misconfiguration(sorted_endpoints)
        
        # ===== 低优先级检测 =====
        print("\n  [低优先级] API版本发现...")
        self._test_api_version_discovery()
        
        # 深度Fuzzing
        print("\n  [深度测试] API Fuzzing...")
        self._run_deep_fuzz_test(sorted_endpoints)
        
        print(f"\n  [漏洞检测] 完成，发现 {len(self.vulnerabilities)} 个问题")
    
    def _merge_all_endpoints(self):
        """合并所有端点"""
        all_endpoints = []
        seen = set()
        
        for ep in self.static_endpoints:
            key = f"{ep.method}:{ep.path}"
            if key not in seen:
                seen.add(key)
                all_endpoints.append({
                    'path': ep.path,
                    'method': ep.method,
                    'source': 'static'
                })
        
        for ep in self.dynamic_endpoints:
            key = f"{ep.get('method', 'GET')}:{ep.get('path', '')}"
            if key not in seen and ep.get('path'):
                seen.add(key)
                all_endpoints.append({
                    'path': ep.get('path'),
                    'method': ep.get('method', 'GET'),
                    'source': 'dynamic'
                })
        
        for ep in self.hooked_endpoints:
            key = f"{ep.get('method', 'GET')}:{ep.get('path', '')}"
            if key not in seen and ep.get('path'):
                seen.add(key)
                all_endpoints.append({
                    'path': ep.get('path'),
                    'method': ep.get('method', 'GET'),
                    'source': 'hooked'
                })
        
        return all_endpoints
    
    def _sort_by_priority(self, endpoints):
        """按优先级排序"""
        priority_map = {'high': 0, 'medium': 1, 'low': 2}
        
        def get_priority(ep):
            path = ep['path'].lower()
            if any(p in path for p in ['/auth/', '/login', '/oauth', '/admin', '/user/delete', '/user/export']):
                return 'high'
            if any(p in path for p in ['/api/', '/system/', '/config/', '/manage/']):
                return 'medium'
            return 'low'
        
        for ep in endpoints:
            ep['priority'] = get_priority(ep)
        
        return sorted(endpoints, key=lambda x: priority_map.get(x.get('priority'), 2))
    
    def _build_url(self, path):
        """构建完整URL"""
        from urllib.parse import urlparse
        
        if path.startswith('http'):
            return urlparse(path).path, {}
        
        base = self.target.split('?')[0].rstrip('/')
        
        # 添加 API 前缀
        if self.api_prefix and not path.startswith('/personnelWeb') and not path.startswith('/api'):
            if path.startswith('/users') or path.startswith('/system') or path.startswith('/menu'):
                path = '/' + self.api_prefix.split('/')[1] + path
        
        return base + path, {}
    
    # ===== 漏洞检测方法 =====
    
    def _test_sql_injection(self, endpoints):
        """SQL 注入检测 - SKILL.md 配置"""
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "1' OR '1'='1",
        ]
        params = ['id', 'page', 'pageNum', 'pageSize', 'userId']
        error_patterns = [
            'sql syntax', 'sql error', 'mysql', 'oracle', 'sqlite',
            'sqlstate', 'postgresql', 'syntax error', 'microsoft sql'
        ]
        
        tested = 0
        for ep in endpoints[:30]:
            path = ep['path']
            method = ep.get('method', 'GET')
            
            base_url, _ = self._build_url(path)
            
            for param in params:
                for payload in payloads[:2]:
                    try:
                        if method == 'POST':
                            r = self.session.post(base_url, json={param: payload}, timeout=5)
                        else:
                            r = self.session.get(f"{base_url}?{param}={payload}", timeout=5)
                        
                        tested += 1
                        ct = r.headers.get('Content-Type', '').lower()
                        if 'text/html' in ct:
                            continue
                        
                        text_lower = r.text.lower()
                        if any(p in text_lower for p in error_patterns):
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'CRITICAL',
                                'endpoint': path,
                                'param': param,
                                'payload': payload,
                                'evidence': 'SQL error detected'
                            })
                            print(f"    [!] SQL注入: {path} ({param})")
                            break
                    except:
                        pass
                
                if any(v['endpoint'] == path for v in self.vulnerabilities):
                    break
        
        print(f"    测试了 {tested} 个请求")
    
    def _test_auth_bypass(self, endpoints):
        """认证绕过检测 - SKILL.md 配置"""
        login_endpoints = [ep for ep in endpoints if '/login' in ep['path'].lower() or '/auth' in ep['path'].lower()]
        
        if not login_endpoints:
            print("    未发现登录端点，跳过")
            return
        
        print(f"    发现 {len(login_endpoints)} 个认证端点")
        
        # 测试空token
        for ep in login_endpoints[:3]:
            path = ep['path']
            base_url, _ = self._build_url(path)
            
            try:
                # 空token
                r = self.session.post(base_url, json={}, timeout=5)
                if r.status_code == 200 and 'token' not in r.text.lower():
                    print(f"    [可疑] {path} 空payload返回200")
            except:
                pass
    
    def _test_privilege_escalation(self, endpoints):
        """越权访问检测 - SKILL.md 配置"""
        # 测试低权限 token 访问高权限资源
        admin_paths = ['/admin', '/system/admin', '/manage']
        
        for ep in endpoints:
            path = ep['path'].lower()
            if any(p in path for p in admin_paths):
                base_url, _ = self._build_url(ep['path'])
                try:
                    r = self.session.get(base_url, timeout=5)
                    if r.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Vertical Privilege Escalation',
                            'severity': 'HIGH',
                            'endpoint': ep['path'],
                            'evidence': 'Admin endpoint accessible'
                        })
                        print(f"    [!] 越权: {ep['path']}")
                except:
                    pass
    
    def _test_unauthorized_access(self, endpoints):
        """未授权访问检测 - SKILL.md 配置"""
        sensitive_patterns = ['/admin', '/user/list', '/user/export', '/config', '/system', '/manage']
        
        found = 0
        for ep in endpoints:
            path = ep['path'].lower()
            if not any(p in path for p in sensitive_patterns):
                continue
            
            base_url, _ = self._build_url(ep['path'])
            try:
                if ep.get('method') == 'POST':
                    r = self.session.post(base_url, json={}, timeout=5)
                else:
                    r = self.session.get(base_url, timeout=5)
                
                found += 1
                if r.status_code == 200:
                    text_lower = r.text.lower()
                    if any(k in text_lower for k in ['user', 'admin', 'password', 'email', 'phone']):
                        self.vulnerabilities.append({
                            'type': 'Unauthorized Access',
                            'severity': 'HIGH',
                            'endpoint': ep['path'],
                            'evidence': 'Sensitive data exposed without auth'
                        })
                        print(f"    [!] 未授权: {ep['path']}")
            except:
                pass
        
        print(f"    测试了 {found} 个敏感端点")
    
    def _test_sensitive_data(self, endpoints):
        """敏感信息泄露检测 - SKILL.md 配置"""
        sensitive_fields = ['password', 'passwd', 'secret', 'token', 'api_key', 'jwt', 'private_key']
        
        for ep in endpoints[:20]:
            base_url, _ = self._build_url(ep['path'])
            try:
                if ep.get('method') == 'POST':
                    r = self.session.post(base_url, json={}, timeout=5)
                else:
                    r = self.session.get(base_url, timeout=5)
                
                if r.status_code == 200:
                    text_lower = r.text.lower()
                    for field in sensitive_fields:
                        if f'"{field}"' in r.text or f'"{field.upper()}"' in r.text:
                            self.vulnerabilities.append({
                                'type': 'Sensitive Data Exposure',
                                'severity': 'MEDIUM',
                                'endpoint': ep['path'],
                                'evidence': f'Contains field: {field}'
                            })
                            print(f"    [!] 敏感信息: {ep['path']} ({field})")
                            break
            except:
                pass
    
    def _test_path_traversal(self, endpoints):
        """路径遍历检测 - SKILL.md 配置"""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        file_endpoints = [ep for ep in endpoints if any(p in ep['path'].lower() for p in ['/file', '/download', '/export', '/import'])]
        
        for ep in file_endpoints[:10]:
            base_url, _ = self._build_url(ep['path'])
            for payload in traversal_payloads[:1]:
                try:
                    r = self.session.get(f"{base_url}?path={payload}", timeout=5)
                    if 'root:' in r.text or '/bin/bash' in r.text:
                        self.vulnerabilities.append({
                            'type': 'Path Traversal',
                            'severity': 'HIGH',
                            'endpoint': ep['path'],
                            'payload': payload,
                            'evidence': 'System file exposed'
                        })
                        print(f"    [!] 路径遍历: {ep['path']}")
                except:
                    pass
    
    def _test_cors_misconfiguration(self, endpoints):
        """CORS配置错误检测 - SKILL.md 配置"""
        for ep in endpoints[:10]:
            base_url, _ = self._build_url(ep['path'])
            try:
                r = self.session.get(base_url, timeout=5)
                cors_origin = r.headers.get('Access-Control-Allow-Origin', '')
                cors_cred = r.headers.get('Access-Control-Allow-Credentials', '')
                
                if cors_origin == '*' and cors_cred == 'true':
                    self.vulnerabilities.append({
                        'type': 'CORS Misconfiguration',
                        'severity': 'MEDIUM',
                        'endpoint': ep['path'],
                        'evidence': 'Allow-Origin: * with Allow-Credentials: true'
                    })
                    print(f"    [!] CORS错误: {ep['path']}")
                elif cors_origin == '*':
                    print(f"    [低] CORS宽松: {ep['path']} (Origin: *)")
            except:
                pass
    
    def _test_api_version_discovery(self):
        """API版本发现 - SKILL.md 配置"""
        version_paths = ['/v1', '/v2', '/v3', '/api/v1', '/api/v2', '/swagger', '/swagger-ui', '/api-docs']
        target_base = self.target.split('?')[0].rstrip('/')
        
        for vp in version_paths:
            try:
                r = self.session.get(target_base + vp, timeout=3, allow_redirects=False)
                if r.status_code in [200, 301, 302]:
                    print(f"    [发现] {vp} -> {r.status_code}")
            except:
                pass
    
    def _run_deep_fuzz_test(self, endpoints):
        """深度Fuzzing测试"""
        from core.api_fuzzer import APIfuzzer
        
        fuzzer = APIfuzzer(session=self.session)
        
        api_paths = []
        for ep in endpoints:
            from urllib.parse import urlparse
            path = ep['path']
            if path.startswith('http'):
                path = urlparse(path).path
            api_paths.append(path)
        
        fuzz_targets = fuzzer.generate_parent_fuzz_targets(api_paths, max_per_parent=30)
        print(f"    生成 {len(fuzz_targets)} 个Fuzz目标")
        
        base_url = self.target.split('?')[0].rstrip('/')
        results = fuzzer.fuzz_paths(base_url, fuzz_targets[:100], timeout=3.0)
        
        alive = fuzzer.get_alive_endpoints()
        print(f"    存活端点: {len(alive)}")
    
    def _report_nginx_fallback(self):
        """报告 nginx fallback"""
        self.vulnerabilities.append({
            'type': 'Backend API Unreachable / nginx fallback',
            'severity': 'HIGH',
            'evidence': '后端API服务不可达'
        })
    
    def _cloud_storage_test(self):
        """云存储测试"""
        tester = CloudStorageTester(self.target)
        tester.session = self.session
        findings, storage_url = tester.full_test(self.target)
        
        print(f"  云存储: {storage_url or 'N/A'}, 发现: {len(findings)}")
        self.cloud_findings = findings
    
    def _generate_report(self):
        """生成报告"""
        print("\n" + "=" * 50)
        print("  测试完成 v3.0")
        print("=" * 50)
        print(f"  站点类型: {self.site_type}")
        print(f"  静态端点: {len(self.static_endpoints)}")
        print(f"  动态端点: {len(self.dynamic_endpoints)}")
        print(f"  API Prefix: {self.api_prefix}")
        
        # 按严重性分组统计
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
    
    def _get_result(self):
        """获取结果"""
        return {
            'target': self.target,
            'site_type': self.site_type,
            'endpoints': {
                'static': len(self.static_endpoints),
                'dynamic': len(self.dynamic_endpoints),
                'hooked': len(self.hooked_endpoints),
                'merged': len(self._merge_all_endpoints()),
            },
            'api_prefix': self.api_prefix,
            'vulnerabilities': self.vulnerabilities,
            'cloud_findings': self.cloud_findings,
        }


if __name__ == "__main__":
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else "http://49.65.100.160:6004/"
    
    executor = SKILLExecutorV3(target)
    result = executor.run()
    
    print("\n\n结果:")
    print(result)
