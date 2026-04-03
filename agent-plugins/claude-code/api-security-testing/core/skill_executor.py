"""
SKILL 执行器 - 智能决策执行

根据 SKILL.md 定义的决策流程：
1. 根据前置检查选择模块
2. 根据静态分析结果判断站点类型
3. 根据父路径探测结果决定后续行动
4. 智能跳过/继续测试
"""

import sys
sys.path.insert(0, '/workspace/skill-play/API-Security-Testing-Optimized')

from core.prerequisite import prerequisite_check
from core.api_parser import APIEndpointParser
from core.cloud_storage_tester import CloudStorageTester


class SKILLExecutor:
    """SKILL 执行器 - 智能决策执行"""
    
    def __init__(self, target: str):
        self.target = target
        self.session = None
        self.playwright_available = False
        self.browser_type = None
        
        # 资产发现结果
        self.parser = None  # 共享的 parser 实例
        self.js_files = []
        self.static_endpoints = []
        self.dynamic_endpoints = []
        self.hooked_endpoints = []
        self.parent_paths = {}
        
        # 测试结果
        self.vulnerabilities = []
        self.cloud_findings = []
        self.api_prefix = None
        
        # 决策状态
        self.site_type = None  # pure_html / jquery_spa / vue_spa / react_spa / login_required
        self.has_real_api = False
        self.has_nginx_fallback = False
        
    def run(self):
        """执行 SKILL 流程"""
        print("=" * 70)
        print("  API Security Testing Skill - 智能执行")
        print("=" * 70)
        print(f"  目标: {self.target}")
        print()
        
        # ========== 阶段 0: 前置检查 ==========
        print("[阶段 0] 前置检查")
        print("-" * 50)
        self._check_prerequisites()
        
        if not self.playwright_available:
            print("  [WARN] Playwright 不可用，使用受限模式")
        
        # ========== 阶段 1: 资产发现 - 静态分析 ==========
        print("\n[阶段 1] 资产发现 - 静态分析")
        print("-" * 50)
        self._static_analysis()
        
        # ========== 阶段 1.1: 判断站点类型 ==========
        print("\n[决策] 判断站点类型")
        print("-" * 50)
        self._detect_site_type()
        
        # ========== 阶段 1.2: 父路径探测 ==========
        print("\n[阶段 1.2] 父路径探测")
        print("-" * 50)
        self._probe_parent_paths()
        
        # ========== 阶段 1.3: 根据决策选择下一步 ==========
        print("\n[决策] 选择后续行动")
        print("-" * 50)
        self._decide_next_action()
        
        # ========== 阶段 2: 漏洞分析 ==========
        if self.has_real_api:
            print("\n[阶段 2] 漏洞分析")
            print("-" * 50)
            self._vulnerability_testing()
        else:
            print("\n[阶段 2] 漏洞分析 - [SKIP]")
            print("-" * 50)
            print("  无真实 API 或 nginx fallback，跳过漏洞测试")
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
        # 使用共享的 parser 实例，避免重复 discover_js_files
        self.parser = APIEndpointParser(self.target, self.session)
        
        # 发现 JS 文件
        self.js_files = self.parser.discover_js_files()
        print(f"  JS 文件: {len(self.js_files)}")
        
        # 解析端点
        self.static_endpoints = self.parser.parse_js_files(self.js_files)
        print(f"  静态端点: {len(self.static_endpoints)}")
        
        for ep in self.static_endpoints[:5]:
            print(f"    {ep.method} {ep.path}")
        
        # 统计端点类型
        path_apis = sum(1 for ep in self.static_endpoints if '/api/' in ep.path)
        print(f"  含 /api/ 路径: {path_apis}")
    
    def _detect_site_type(self):
        """判断站点类型"""
        # 检测前端框架（从 JS 文件内容或 HTML）
        html = self.session.get(self.target, timeout=10).text.lower()
        
        frontend = 'Unknown'
        ui = 'Unknown'
        
        # 从 HTML 检测
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
        
        # 根据 JS 文件数量和端点特征判断站点类型
        if len(self.js_files) == 0:
            self.site_type = 'pure_html'
            print(f"  站点类型: 纯 HTML (无 JS)")
        elif frontend == 'Unknown' and len(self.js_files) > 0:
            # 可能是 JS 渲染的 SPA（HTML 不包含框架关键字）
            self.site_type = 'modern_spa'
            frontend = 'Vue.js/React (推断)'
            print(f"  站点类型: 现代 SPA (基于 JS 文件)")
        elif frontend in ['Vue.js', 'React', 'Angular']:
            self.site_type = 'modern_spa'
            print(f"  站点类型: 现代 SPA ({frontend})")
        elif frontend == 'jQuery':
            self.site_type = 'jquery_spa'
            print(f"  站点类型: jQuery SPA")
        else:
            self.site_type = 'unknown'
            print(f"  站点类型: 未知")
        
        print(f"  前端框架: {frontend}")
        print(f"  UI 框架: {ui}")
        print(f"  JS 文件: {len(self.js_files)}")
        
        # 决策：是否需要动态分析
        if self.site_type in ['modern_spa', 'jquery_spa'] or len(self.js_files) > 0:
            print(f"  [建议] 启用动态分析 (发现 {len(self.js_files)} 个 JS 文件)")
        else:
            print(f"  [建议] 可跳过动态分析")
    
    def _probe_parent_paths(self):
        """父路径探测 - 使用共享的 parser 实例"""
        # parser.parse_js_files 已经提取了父路径
        self.parent_paths = self.parser.probe_parent_paths()
        
        real_apis = sum(1 for p in self.parent_paths.values() if p.get('is_api'))
        html_fallback = sum(1 for p in self.parent_paths.values() if not p.get('is_api'))
        
        print(f"  父路径: {len(self.parent_paths)}")
        print(f"  JSON API: {real_apis}")
        print(f"  HTML fallback: {html_fallback}")
        
        if real_apis > 0:
            self.has_real_api = True
            print(f"  [OK] 发现真实 API")
        else:
            self.has_real_api = False
            if html_fallback > 0:
                self.has_nginx_fallback = True
                print(f"  [WARN] nginx fallback")
            else:
                print(f"  [INFO] 未发现 API 响应")
        
        # 保存检测到的 API 前缀
        for p in self.parent_paths.values():
            if p.get('prefix'):
                self.api_prefix = p.get('prefix')
                print(f"  [API Prefix] {self.api_prefix}")
                break
    
    def _decide_next_action(self):
        """决策后续行动"""
        print("\n  决策分析:")
        
        # 决策 1: 是否执行动态分析
        if self.site_type in ['modern_spa', 'jquery_spa'] and self.playwright_available:
            print("    - [执行] 动态分析 (SPA 站点)")
            self._dynamic_analysis()
        else:
            skip_reason = []
            if self.site_type not in ['modern_spa', 'jquery_spa']:
                skip_reason.append("非 SPA")
            if not self.playwright_available:
                skip_reason.append("Playwright 不可用")
            print(f"    - [跳过] 动态分析 ({', '.join(skip_reason)})")
        
        # 决策 2: 是否执行 API Hook
        if self.playwright_available and self.has_real_api:
            print("    - [执行] API Hook (有真实 API)")
            self._api_hook()
        else:
            skip_reason = []
            if not self.playwright_available:
                skip_reason.append("Playwright 不可用")
            if not self.has_real_api:
                skip_reason.append("无真实 API")
            print(f"    - [跳过] API Hook ({', '.join(skip_reason)})")
        
        # 决策 3: 是否执行漏洞测试
        if self.has_real_api:
            print("    - [执行] 漏洞测试 (有真实 API)")
        else:
            print("    - [跳过] 漏洞测试 (无真实 API)")
    
    def _dynamic_analysis(self):
        """动态分析"""
        print("\n  [动态分析] 启动 Playwright...")
        try:
            from core.dynamic_api_analyzer import DynamicAPIAnalyzer
            
            analyzer = DynamicAPIAnalyzer(self.target)
            results = analyzer.analyze_full()
            
            count = len(results.get('endpoints', []))
            print(f"  [动态分析] 发现 {count} 个端点")
            
            self.dynamic_endpoints = results.get('endpoints', [])
            
        except Exception as e:
            print(f"  [动态分析] 失败: {e}")
    
    def _api_hook(self):
        """API Hook"""
        print("\n  [API Hook] 启动 Hook...")
        try:
            from core.api_interceptor import APIInterceptor
            
            interceptor = APIInterceptor(self.target)
            results = interceptor.hook_all_apis()
            
            count = len(results.get('endpoints', []))
            print(f"  [API Hook] 捕获 {count} 个 API 调用")
            
            self.hooked_endpoints = results.get('endpoints', [])
            
        except Exception as e:
            print(f"  [API Hook] 失败: {e}")
    
    def _vulnerability_testing(self):
        """漏洞测试"""
        print("  [漏洞测试] 执行...")
        
        # 合并所有端点（统一格式）
        all_endpoints = []
        
        # 静态端点
        for ep in self.static_endpoints:
            all_endpoints.append({
                'path': ep.path,
                'method': ep.method,
            })
        
        # 动态端点
        for ep in self.dynamic_endpoints:
            all_endpoints.append({
                'path': ep.get('path', ''),
                'method': ep.get('method', 'GET'),
            })
        
        # Hook 端点
        for ep in self.hooked_endpoints:
            all_endpoints.append({
                'path': ep.get('path', ''),
                'method': ep.get('method', 'GET'),
            })
        
        # 去重
        seen = set()
        unique_endpoints = []
        for ep in all_endpoints:
            key = f"{ep['method']}:{ep['path']}"
            if key not in seen and ep['path']:
                seen.add(key)
                unique_endpoints.append(ep)
        
        print(f"  总端点: {len(unique_endpoints)}")
        
        # 简化测试：只测 SQL 注入
        sqli_payloads = ["' OR '1'='1"]
        
        for ep in unique_endpoints[:10]:
            path = ep['path']
            method = ep['method']
            
            if method != 'GET':
                continue
            
            # 使用完整 URL（包含 API 前缀）
            if self.api_prefix:
                url = f"http://{self.target.replace('http://', '').split('/')[0]}{self.api_prefix}{path.lstrip('/')}"
            else:
                url = self.target.rstrip('/') + path
            
            if '?' not in url:
                url = url + '?id=1'
            
            try:
                r = self.session.get(url.replace('id=1', sqli_payloads[0]), timeout=5)
                ct = r.headers.get('Content-Type', '').lower()
                
                if 'text/html' in ct:
                    continue
                
                # 检测 SQL 错误
                text_lower = r.text.lower()
                sql_patterns = ['sql syntax', 'sql error', 'mysql', 'oracle', 
                               'sqlite', 'sqlstate', 'postgresql']
                if any(p in text_lower for p in sql_patterns):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'CRITICAL',
                        'endpoint': path,
                    })
                    print(f"    [!] {path}: SQL注入")
                    
            except:
                pass
        
        print(f"  发现漏洞: {len(self.vulnerabilities)}")
    
    def _report_nginx_fallback(self):
        """报告 nginx fallback 问题"""
        self.vulnerabilities.append({
            'type': 'Backend API Unreachable / nginx fallback',
            'severity': 'HIGH',
            'endpoint': 'Multiple paths',
            'evidence': f'{len(self.parent_paths)} paths return HTML (nginx fallback)'
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
        total_endpoints = len(self.static_endpoints) + len(self.dynamic_endpoints)
        
        print("\n" + "=" * 50)
        print("  测试完成")
        print("=" * 50)
        print(f"  站点类型: {self.site_type}")
        print(f"  静态端点: {len(self.static_endpoints)}")
        print(f"  动态端点: {len(self.dynamic_endpoints)}")
        print(f"  Hook 端点: {len(self.hooked_endpoints)}")
        print(f"  JSON API: {sum(1 for p in self.parent_paths.values() if p.get('is_api'))}")
        print(f"  漏洞: {len(self.vulnerabilities)}")
        print(f"  云存储: {len(self.cloud_findings)}")
    
    def _get_result(self):
        """获取结果"""
        return {
            'target': self.target,
            'site_type': self.site_type,
            'endpoints': {
                'static': len(self.static_endpoints),
                'dynamic': len(self.dynamic_endpoints),
                'hooked': len(self.hooked_endpoints),
                'parent_paths': len(self.parent_paths),
                'json_api': sum(1 for p in self.parent_paths.values() if p.get('is_api')),
            },
            'vulnerabilities': self.vulnerabilities,
            'cloud_findings': self.cloud_findings,
            'api_prefix': self.api_prefix,
        }


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "http://58.216.151.148:8972/do/mh/jtmhindex"
    
    executor = SKILLExecutor(target)
    result = executor.run()
    
    print("\n\n结果:")
    print(result)
