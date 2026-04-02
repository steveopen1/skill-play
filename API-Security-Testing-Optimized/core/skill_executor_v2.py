"""
SKILL 执行器 v2.0 - 配置驱动执行

根据 SKILL.md v2.0 定义的 execution_config:
1. 解析配置驱动的执行流程
2. 综合判断 API 存在性（静态 + 动态）
3. 端点合并（静态 + 动态 + Hook）
4. API前缀多源提取
5. 认证端点优先测试
"""

import sys
sys.path.insert(0, '/workspace/skill-play/API-Security-Testing-Optimized')

from core.prerequisite import prerequisite_check
from core.api_parser import APIEndpointParser
from core.cloud_storage_tester import CloudStorageTester


class SKILLExecutorV2:
    """SKILL 执行器 v2.0 - 配置驱动"""
    
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
        
        # v2.0 新增：API前缀多源提取
        self.api_prefix = None
        self.api_prefix_sources = {}
        
        # 测试结果
        self.vulnerabilities = []
        self.cloud_findings = []
        
        # 决策状态
        self.site_type = None
        self.has_real_api = False
        self.has_dynamic_endpoints = False
        self.html_fallback_all = False
    
    def run(self):
        """执行 SKILL 流程 v2.0"""
        print("=" * 70)
        print("  API Security Testing Skill v2.0 - 配置驱动执行")
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
        
        # 1.1 静态分析
        print("\n[1.1] 静态分析")
        self._static_analysis()
        
        # 1.2 站点类型检测
        print("\n[1.2] 站点类型检测")
        self._detect_site_type()
        
        # 1.3 父路径探测
        print("\n[1.3] 父路径探测")
        self._probe_parent_paths()
        
        # 1.4 动态分析 (条件执行)
        print("\n[1.4] 动态分析")
        if self.site_type in ['modern_spa', 'jquery_spa'] and self.playwright_available:
            self._dynamic_analysis()
        else:
            print("  [跳过] 非SPA或Playwright不可用")
        
        # 1.5 API Hook (条件执行)
        print("\n[1.5] API Hook")
        if self.playwright_available and (self.has_real_api or self.has_dynamic_endpoints):
            self._api_hook()
        else:
            print("  [跳过] 无API或Playwright不可用")
        
        # ========== 阶段 2: 漏洞分析 ==========
        print("\n[阶段 2] 漏洞分析")
        print("-" * 50)
        
        # v2.0 修复：综合判断
        self._update_decision_state()
        
        if self.has_real_api or self.has_dynamic_endpoints:
            self._vulnerability_testing()
        else:
            if self.html_fallback_all:
                print("  [SKIP] nginx fallback，报告问题")
                self._report_nginx_fallback()
            else:
                print("  [继续] 无API但非fallback，执行测试")
                self._vulnerability_testing()
        
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
        ui = 'Unknown'
        
        if 'vue' in html:
            frontend = 'Vue.js'
        if 'react' in html:
            frontend = 'React'
        if 'angular' in html:
            frontend = 'Angular'
        if 'jquery' in html:
            frontend = 'jQuery'
        
        if 'element-ui' in html or 'element ui' in html:
            ui = 'ElementUI'
        if 'ant-design' in html:
            ui = 'Ant Design'
        
        if len(self.js_files) == 0:
            self.site_type = 'pure_html'
        elif frontend == 'Unknown' and len(self.js_files) > 0:
            self.site_type = 'modern_spa'
            frontend = 'Vue.js/React (推断)'
        elif frontend in ['Vue.js', 'React', 'Angular']:
            self.site_type = 'modern_spa'
        elif frontend == 'jQuery':
            self.site_type = 'jquery_spa'
        else:
            self.site_type = 'unknown'
        
        print(f"  站点类型: {self.site_type}")
        print(f"  前端框架: {frontend}")
        print(f"  UI 框架: {ui}")
    
    def _probe_parent_paths(self):
        """父路径探测"""
        self.parent_paths = self.parser.probe_parent_paths()
        
        json_api_count = sum(1 for p in self.parent_paths.values() if p.get('is_api'))
        html_fallback_count = len(self.parent_paths) - json_api_count
        
        print(f"  父路径: {len(self.parent_paths)}")
        print(f"  JSON API: {json_api_count}")
        print(f"  HTML fallback: {html_fallback_count}")
        
        # v2.0: 从父路径提取API前缀
        for p in self.parent_paths.values():
            if p.get('prefix'):
                self.api_prefix_sources['parent_paths'] = p.get('prefix')
                self.api_prefix = p.get('prefix')
                print(f"  [API Prefix] from parent_paths: {self.api_prefix}")
                break
        
        # v2.0: 判断 has_real_api
        if json_api_count > 0:
            self.has_real_api = True
            print(f"  [OK] 父路径发现真实 API")
        else:
            self.has_real_api = False
    
    def _dynamic_analysis(self):
        """动态分析 v2.0"""
        print("  [动态分析] 启动 Playwright...")
        try:
            from core.dynamic_api_analyzer import DynamicAPIAnalyzer
            from urllib.parse import urlparse
            
            analyzer = DynamicAPIAnalyzer(self.target)
            results = analyzer.analyze_full()
            
            count = len(results.get('endpoints', []))
            print(f"  [动态分析] 发现 {count} 个端点")
            
            self.dynamic_endpoints = results.get('endpoints', [])
            
            # v2.0: 从动态端点URL自动提取API前缀
            target_host = urlparse(self.target).netloc
            for ep in self.dynamic_endpoints:
                ep_path = ep.get('path', '')
                if ep_path.startswith('http'):
                    ep_host = urlparse(ep_path).netloc
                    ep_path_only = urlparse(ep_path).path
                    if ep_host == target_host and ep_path_only.startswith('/'):
                        # 提取API前缀：通常是 /xxx/xxx 格式
                        parts = ep_path_only.strip('/').split('/')
                        if len(parts) >= 2:
                            potential_prefix = '/' + '/'.join(parts[:2])
                            if potential_prefix not in ['/login', '/logout', '/static', '/js', '/css']:
                                self.api_prefix_sources['dynamic'] = potential_prefix
                                self.api_prefix = potential_prefix
                                print(f"  [API Prefix] from dynamic: {self.api_prefix}")
                                break
            
            for ep in self.dynamic_endpoints[:5]:
                print(f"    {ep.get('method', 'GET')} {ep.get('path')}")
            
            # v2.0: 更新动态端点状态
            if count > 0:
                self.has_dynamic_endpoints = True
                print(f"  [OK] 动态分析发现真实 API")
            
        except Exception as e:
            print(f"  [动态分析] 失败: {e}")
    
    def _api_hook(self):
        """API Hook"""
        print("  [API Hook] 启动 Hook...")
        try:
            from core.api_interceptor import APIInterceptor
            
            interceptor = APIInterceptor(self.target)
            results = interceptor.hook_all_apis()
            
            count = len(results.get('endpoints', []))
            print(f"  [API Hook] 捕获 {count} 个 API 调用")
            
            self.hooked_endpoints = results.get('endpoints', [])
            
        except Exception as e:
            print(f"  [API Hook] 失败: {e}")
    
    def _update_decision_state(self):
        """v2.0: 更新决策状态 - 综合判断"""
        json_api_count = sum(1 for p in self.parent_paths.values() if p.get('is_api'))
        dynamic_count = len(self.dynamic_endpoints)
        
        print("\n[决策] 综合判断 API 存在性")
        print(f"  - 父路径 JSON API: {json_api_count}")
        print(f"  - 动态端点: {dynamic_count}")
        
        # v2.0 核心修复：综合判断
        # has_real_api: 任意来源有API即认为有真实API
        self.has_real_api = json_api_count > 0 or dynamic_count > 0
        self.has_dynamic_endpoints = dynamic_count > 0
        
        # v2.0: 只有当父路径存在但全返回HTML，且无动态端点时才是真正的fallback
        # 父路径探测失败但有动态端点，说明API是动态加载的，不是nginx fallback
        
        # v2.0: html_fallback_all 判断
        # 只有当没有任何API发现时才认为是fallback
        self.html_fallback_all = (
            len(self.parent_paths) > 0 and 
            json_api_count == 0 and 
            dynamic_count == 0
        )
        
        print(f"  has_real_api: {self.has_real_api}")
        print(f"  has_dynamic_endpoints: {self.has_dynamic_endpoints}")
        print(f"  html_fallback_all: {self.html_fallback_all}")
    
    def _vulnerability_testing(self):
        """漏洞测试 v2.0 - 集成API Fuzzer进行深度测试"""
        
        print("  [漏洞测试] 启动深度渗透测试...")
        
        # 导入fuzzer
        try:
            from core.api_fuzzer import APIfuzzer, auto_fuzz
            fuzzer_available = True
        except ImportError:
            fuzzer_available = False
            print("  [警告] API Fuzzer模块不可用，使用基础测试")
        
        # v2.0: 合并所有端点
        all_endpoints = self._merge_all_endpoints()
        
        # v2.0: 按优先级排序
        sorted_endpoints = self._sort_by_priority(all_endpoints)
        
        print(f"  [漏洞测试] 总端点: {len(sorted_endpoints)}")
        
        # 打印认证端点详情
        auth_count = 0
        for ep in sorted_endpoints:
            if self._is_auth_endpoint(ep['path']):
                auth_count += 1
        print(f"  [漏洞测试] 认证端点: {auth_count}")
        
        # ========== 深度Fuzzing测试 ==========
        if fuzzer_available:
            print("\n  [深度测试] 执行API Fuzzing...")
            self._run_deep_fuzz_test(sorted_endpoints)
        
        # ========== 基础漏洞测试 ==========
        print("\n  [基础测试] SQL注入检测...")
        self._test_sql_injection(sorted_endpoints)
        
        # ========== 未授权访问测试 ==========
        print("\n  [基础测试] 未授权访问检测...")
        self._test_unauthorized_access(sorted_endpoints)
        
        print(f"\n  发现漏洞: {len(self.vulnerabilities)}")
        
        # 打印漏洞摘要
        if self.vulnerabilities:
            print("\n  [漏洞摘要]")
            for v in self.vulnerabilities[:10]:
                print(f"    [{v['severity']}] {v['type']} - {v.get('endpoint', 'N/A')}")
    
    def _run_deep_fuzz_test(self, endpoints):
        """深度Fuzz测试"""
        from core.api_fuzzer import APIfuzzer
        
        fuzzer = APIfuzzer(session=self.session)
        
        # 提取路径列表
        api_paths = []
        for ep in endpoints:
            path = ep['path']
            if path.startswith('http'):
                from urllib.parse import urlparse
                path = urlparse(path).path
            api_paths.append(path)
        
        # 生成fuzz目标
        fuzz_targets = fuzzer.generate_parent_fuzz_targets(api_paths, max_per_parent=30)
        print(f"  [Fuzz] 生成 {len(fuzz_targets)} 个测试目标")
        
        # 执行fuzz
        base_url = self.target.split('?')[0].rstrip('/')
        results = fuzzer.fuzz_paths(base_url, fuzz_targets[:100], timeout=3.0)
        
        # 分析结果
        alive = fuzzer.get_alive_endpoints()
        high_value = fuzzer.get_high_value_endpoints()
        
        print(f"  [Fuzz] 存活端点: {len(alive)}")
        print(f"  [Fuzz] 高价值端点: {len(high_value)}")
        
        # 发现新端点
        for r in high_value[:5]:
            print(f"    [发现] {r.method} {r.path} -> {r.status_code}")
    
    def _test_sql_injection(self, endpoints):
        """SQL注入测试"""
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "1' OR '1'='1",
            "' OR ''='",
        ]
        
        test_params = ['id', 'page', 'pageNum', 'pageSize', 'userId', 'id']
        
        for ep in endpoints[:20]:
            path = ep['path']
            method = ep.get('method', 'GET')
            priority = ep.get('priority', 'low')
            
            # 构建URL - 正确添加API前缀
            if path.startswith('http'):
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(path)
                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                existing_params = parse_qs(parsed.query)
            else:
                base = self.target.split('?')[0].rstrip('/')
                # v2.0: 如果静态端点没有前缀，但有已知的api_prefix，添加前缀
                path_to_add = path
                if self.api_prefix and not path.startswith('/personnelWeb'):
                    # 从 /personnelWeb/auth 提取 /personnelWeb
                    prefix_base = '/' + self.api_prefix.split('/')[1]
                    if path.startswith('/users') or path.startswith('/system') or path.startswith('/menu'):
                        path_to_add = prefix_base + path
                        print(f"    [修正] {path} -> {path_to_add}")
                base = base + path_to_add
                existing_params = {}
            
            # 添加测试参数
            for param in test_params:
                if param not in existing_params:
                    test_url = f"{base}?{param}="
                    break
            else:
                continue
            
            for payload in sqli_payloads[:2]:
                try:
                    if method == 'POST':
                        r = self.session.post(
                            base,
                            json={param: payload for param in test_params},
                            timeout=5
                        )
                    else:
                        r = self.session.get(test_url + payload, timeout=5)
                    
                    ct = r.headers.get('Content-Type', '').lower()
                    
                    # 检查SQL错误
                    text_lower = r.text.lower()
                    sql_patterns = [
                        'sql syntax', 'sql error', 'mysql', 'oracle',
                        'sqlite', 'sqlstate', 'postgresql', 'syntax error',
                        'microsoft sql', 'odbc', 'ora-', 'pgsql'
                    ]
                    if any(p in text_lower for p in sql_patterns):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'endpoint': path,
                            'param': param,
                            'payload': payload,
                            'priority': priority,
                            'evidence': 'SQL error detected'
                        })
                        print(f"    [!] SQL注入: {path} ({param}={payload})")
                        break
                    
                    # 检查异常响应
                    if r.status_code == 500 and 'error' in text_lower:
                        self.vulnerabilities.append({
                            'type': 'Potential SQL Injection',
                            'severity': 'MEDIUM',
                            'endpoint': path,
                            'param': param,
                            'payload': payload,
                            'priority': priority,
                            'evidence': f'Server error {r.status_code}'
                        })
                        
                except:
                    pass
    
    def _test_unauthorized_access(self, endpoints):
        """未授权访问测试"""
        sensitive_patterns = [
            '/admin', '/user/list', '/user/export', '/config',
            '/system', '/manage', '/dashboard', '/api/users'
        ]
        
        for ep in endpoints:
            path = ep['path']
            method = ep.get('method', 'GET')
            
            # 检查敏感路径
            if not any(p in path.lower() for p in sensitive_patterns):
                continue
            
            # 构建URL
            if path.startswith('http'):
                from urllib.parse import urlparse
                url = f"{urlparse(path).scheme}://{urlparse(path).netloc}{urlparse(path).path}"
            else:
                url = self.target.split('?')[0].rstrip('/') + path
            
            try:
                # 不带认证信息访问
                if method == 'POST':
                    r = self.session.post(url, json={}, timeout=5)
                else:
                    r = self.session.get(url, timeout=5)
                
                # 检查是否返回敏感数据（未授权访问成功）
                if r.status_code == 200:
                    text_lower = r.text.lower()
                    if any(k in text_lower for k in ['user', 'admin', 'password', 'email', 'phone']):
                        self.vulnerabilities.append({
                            'type': 'Unauthorized Access',
                            'severity': 'HIGH',
                            'endpoint': path,
                            'method': method,
                            'evidence': f'Sensitive data exposed without auth'
                        })
                        print(f"    [!] 未授权访问: {method} {path}")
                
                # 401/403 -> 需要认证（正常）
                # 200 + 无敏感数据 -> 可能不需要认证
                
            except:
                pass
    
    def _merge_all_endpoints(self):
        """v2.0: 合并所有端点"""
        all_endpoints = []
        seen = set()
        
        # 静态端点
        for ep in self.static_endpoints:
            key = f"{ep.method}:{ep.path}"
            if key not in seen:
                seen.add(key)
                all_endpoints.append({
                    'path': ep.path,
                    'method': ep.method,
                    'source': 'static'
                })
        
        # 动态端点 (v2.0 新增)
        for ep in self.dynamic_endpoints:
            key = f"{ep.get('method', 'GET')}:{ep.get('path', '')}"
            if key not in seen and ep.get('path'):
                seen.add(key)
                all_endpoints.append({
                    'path': ep.get('path'),
                    'method': ep.get('method', 'GET'),
                    'source': 'dynamic'
                })
        
        # Hook 端点
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
    
    def _is_auth_endpoint(self, path):
        """v2.0: 判断是否为认证端点"""
        auth_patterns = [
            '/auth/', '/login', '/oauth/', '/user/login',
            '/api/user/login', '/api/auth/', '/token', '/sso'
        ]
        path_lower = path.lower()
        return any(p in path_lower for p in auth_patterns)
    
    def _sort_by_priority(self, endpoints):
        """v2.0: 按优先级排序端点"""
        priority_map = {'high': 0, 'medium': 1, 'low': 2}
        
        def get_priority(ep):
            if self._is_auth_endpoint(ep['path']):
                return 'high'
            if '/api/' in ep['path'] or '/prod-api/' in ep['path']:
                return 'medium'
            return 'low'
        
        for ep in endpoints:
            ep['priority'] = get_priority(ep)
        
        return sorted(endpoints, key=lambda x: priority_map.get(x.get('priority'), 2))
    
    def _report_nginx_fallback(self):
        """报告 nginx fallback 问题"""
        self.vulnerabilities.append({
            'type': 'Backend API Unreachable / nginx fallback',
            'severity': 'HIGH',
            'endpoint': 'Multiple paths',
            'evidence': '父路径全部返回HTML，且无动态端点'
        })
        print(f"  添加问题: nginx fallback")
    
    def _cloud_storage_test(self):
        """云存储测试"""
        tester = CloudStorageTester(self.target)
        tester.session = self.session
        findings, storage_url = tester.full_test(self.target)
        
        print(f"  云存储: {storage_url}")
        print(f"  发现: {len(findings)}")
        
        self.cloud_findings = findings
    
    def _generate_report(self):
        """生成报告"""
        json_api_count = sum(1 for p in self.parent_paths.values() if p.get('is_api'))
        
        print("\n" + "=" * 50)
        print("  测试完成 v2.0")
        print("=" * 50)
        print(f"  站点类型: {self.site_type}")
        print(f"  静态端点: {len(self.static_endpoints)}")
        print(f"  动态端点: {len(self.dynamic_endpoints)}")
        print(f"  Hook 端点: {len(self.hooked_endpoints)}")
        print(f"  JSON API: {json_api_count}")
        print(f"  API Prefix: {self.api_prefix}")
        print(f"  漏洞: {len(self.vulnerabilities)}")
        print(f"  云存储: {len(self.cloud_findings)}")
        
        if self.api_prefix_sources:
            print(f"  API Prefix来源: {self.api_prefix_sources}")
    
    def _get_result(self):
        """获取结果"""
        json_api_count = sum(1 for p in self.parent_paths.values() if p.get('is_api'))
        
        return {
            'target': self.target,
            'site_type': self.site_type,
            'endpoints': {
                'static': len(self.static_endpoints),
                'dynamic': len(self.dynamic_endpoints),
                'hooked': len(self.hooked_endpoints),
                'parent_paths': len(self.parent_paths),
                'json_api': json_api_count,
                'merged': len(self._merge_all_endpoints()),
            },
            'api_prefix': self.api_prefix,
            'api_prefix_sources': self.api_prefix_sources,
            'decision': {
                'has_real_api': self.has_real_api,
                'has_dynamic_endpoints': self.has_dynamic_endpoints,
                'html_fallback_all': self.html_fallback_all,
            },
            'vulnerabilities': self.vulnerabilities,
            'cloud_findings': self.cloud_findings,
        }


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "http://114.220.238.206:9528/login?redirect=%2Fdashboard"
    
    executor = SKILLExecutorV2(target)
    result = executor.run()
    
    print("\n\n结果:")
    print(result)
