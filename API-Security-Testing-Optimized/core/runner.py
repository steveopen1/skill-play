#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SKILL.md 的可执行实现

本模块实现了 SKILL.md 描述的完整测试流程：
1. 前置检查 - 自动检查/安装依赖
2. 编排执行 - 调用 orchestrator
3. 报告生成 - 输出 Markdown 格式

使用方式:
    # 方式1: 命令行
    python3 -m core.runner http://target.com
    
    # 方式2: 导入
    from core.runner import run_skill
    result = run_skill('http://target.com')
    
    # 方式3: SKILL.md 中引用
    cd /workspace/API-Security-Testing-Optimized
    python3 -c "from core.runner import run_skill; run_skill('http://target')"
"""

import sys
import json
import time
import logging
from datetime import datetime
from typing import Dict, Optional, List

# 确保 core 模块可导入
sys.path.insert(0, '/workspace/skill-play/API-Security-Testing-Optimized')

logger = logging.getLogger(__name__)


class PrerequisiteChecker:
    """前置检查器 - 自动检查和修复依赖"""
    
    @staticmethod
    def check_playwright() -> bool:
        """检查 playwright 是否可用"""
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                browser.close()
            return True
        except Exception as e:
            logger.warning(f"Playwright 检查失败: {e}")
            return False
    
    @staticmethod
    def fix_playwright() -> bool:
        """尝试修复 playwright"""
        import subprocess
        
        print("    [TRY] 尝试安装 playwright 依赖...")
        
        # 尝试安装系统依赖
        try:
            result = subprocess.run(
                ['playwright', 'install-deps', 'chromium'],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                print("    [OK] 系统依赖安装完成")
        except Exception as e:
            print(f"    [WARN] install-deps 失败: {e}")
        
        # 尝试安装 chromium
        try:
            result = subprocess.run(
                ['playwright', 'install', 'chromium'],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                print("    [OK] chromium 安装完成")
        except Exception as e:
            print(f"    [WARN] chromium 安装失败: {e}")
        
        # 重新验证
        return PrerequisiteChecker.check_playwright()
    
    @staticmethod
    def check_requests() -> bool:
        """检查 requests 是否可用"""
        try:
            import requests
            return True
        except ImportError:
            return False
    
    @staticmethod
    def check_all() -> Dict[str, bool]:
        """检查所有依赖"""
        results = {
            'playwright': PrerequisiteChecker.check_playwright(),
            'requests': PrerequisiteChecker.check_requests(),
        }
        return results


class EndpointDiscovery:
    """端点发现器 - 整合多种发现能力"""
    
    def __init__(self, target: str, session):
        self.target = target
        self.session = session
    
    def discover_v35_js_analyzer(self) -> List:
        """使用 V35JSAnalyzer 发现端点"""
        from core.deep_api_tester_v55 import V35JSAnalyzer, APIEndpoint
        
        print("    [V35JSAnalyzer] JS 文件分析...")
        
        js_analyzer = V35JSAnalyzer(self.target, self.session)
        js_files = self._discover_js_files()
        print(f"    [V35JSAnalyzer] 发现 {len(js_files)} 个 JS 文件")
        
        all_endpoints = []
        for js_url in js_files:
            result = js_analyzer.analyze_js(js_url)
            all_endpoints.extend(result['endpoints'])
        
        # 去重
        seen = set()
        unique = []
        for ep in all_endpoints:
            key = f"{ep.method}:{ep.url}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        
        print(f"    [V35JSAnalyzer] 发现 {len(unique)} 个唯一端点")
        return unique
    
    def discover_swagger(self) -> List[str]:
        """发现 Swagger/API 文档"""
        swagger_urls = []
        
        common_paths = [
            '/swagger.json', '/swagger-ui.html', '/api-docs',
            '/v1/api-docs', '/doc.html', '/swagger.yaml'
        ]
        
        for path in common_paths:
            url = self.target.rstrip('/') + path
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200 and 'swagger' in r.text.lower():
                    swagger_urls.append(url)
                    print(f"    [Swagger] 发现: {url}")
            except:
                pass
        
        return swagger_urls
    
    def discover_intelligent_guess(self) -> List[str]:
        """SPA 模式智能路径猜测"""
        paths = []
        
        common_paths = [
            '/api/users', '/api/user', '/api/admin', '/api/auth',
            '/api/login', '/api/logout', '/api/profile', '/api/settings',
            '/auth/login', '/auth/logout', '/auth/token',
            '/user/info', '/user/list', '/user/profile',
            '/admin/users', '/admin/config', '/admin/settings',
        ]
        
        for path in common_paths:
            url = self.target.rstrip('/') + path
            try:
                r = self.session.get(url, timeout=3)
                if r.status_code == 200:
                    ct = r.headers.get('Content-Type', '')
                    if 'json' in ct.lower() or '{' in r.text[:100]:
                        paths.append(path)
                        print(f"    [猜测] 发现: {path}")
            except:
                pass
        
        return paths
    
    def _discover_js_files(self) -> List[str]:
        """发现 JS 文件"""
        import re
        
        js_files = []
        
        try:
            resp = self.session.get(self.target, timeout=10)
            patterns = [
                r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, resp.text)
                for match in matches:
                    if match.startswith('/'):
                        url = self.target.rstrip('/') + match
                    elif match.startswith('http'):
                        url = match
                    else:
                        continue
                    
                    if self.target.replace('http://', '').replace('https://', '').split('/')[0] in url:
                        if url not in js_files:
                            js_files.append(url)
        except Exception as e:
            logger.warning(f"JS 文件发现失败: {e}")
        
        return js_files


class ReportGenerator:
    """报告生成器"""
    
    @staticmethod
    def generate(results: Dict) -> str:
        """生成 Markdown 报告"""
        
        report = []
        report.append("# API 安全测试报告")
        report.append("")
        report.append(f"**目标**: {results.get('target', 'N/A')}")
        report.append(f"**时间**: {results.get('timestamp', 'N/A')}")
        report.append(f"**耗时**: {results.get('duration', 0):.1f}s")
        report.append("")
        
        # 统计
        report.append("## 发现统计")
        report.append("")
        
        endpoints = results.get('endpoints', [])
        vulnerabilities = results.get('vulnerabilities', [])
        
        report.append(f"- API 端点: {len(endpoints)}")
        report.append(f"- 漏洞: {len(vulnerabilities)}")
        report.append("")
        
        # 端点详情
        if endpoints:
            report.append("## API 端点")
            report.append("")
            for ep in endpoints[:50]:  # 限制输出
                method = ep.get('method', 'GET')
                url = ep.get('url', ep.get('path', ''))
                source = ep.get('source', '')
                report.append(f"- `{method}` {url} ({source})")
            report.append("")
        
        # 漏洞详情
        if vulnerabilities:
            report.append("## 漏洞详情")
            report.append("")
            for v in vulnerabilities:
                report.append(f"### {v.get('type', 'Unknown')}")
                report.append(f"- **严重程度**: {v.get('severity', 'N/A')}")
                report.append(f"- **端点**: {v.get('endpoint', 'N/A')}")
                report.append(f"- **证据**: {v.get('evidence', 'N/A')}")
                report.append("")
        
        # 技术栈
        if results.get('tech_stack'):
            report.append("## 技术栈")
            report.append("")
            for key, value in results['tech_stack'].items():
                report.append(f"- {key}: {value}")
            report.append("")
        
        # 洞察
        if results.get('insights'):
            report.append("## 安全洞察")
            report.append("")
            for insight in results['insights'][:10]:
                report.append(f"- {insight}")
            report.append("")
        
        return "\n".join(report)


def run_skill(
    target: str,
    use_orchestrator: bool = True,
    enable_fuzzing: bool = True,
    enable_testing: bool = True,
    max_iterations: int = 50,
    max_duration: float = 1800.0
) -> Dict:
    """
    执行 SKILL.md 描述的完整测试流程
    
    Args:
        target: 目标 URL
        use_orchestrator: 是否使用编排器
        enable_fuzzing: 是否启用 fuzzing
        enable_testing: 是否启用漏洞测试
        max_iterations: 最大迭代次数
        max_duration: 最大运行时长（秒）
    
    Returns:
        测试结果字典
    """
    print("=" * 70)
    print("  API Security Testing Skill")
    print("=" * 70)
    print()
    
    results = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'endpoints': [],
        'vulnerabilities': [],
        'insights': [],
        'tech_stack': {},
    }
    
    # ========== 阶段 0: 前置检查 ==========
    print("[0] 前置检查")
    print("-" * 70)
    
    prereq = PrerequisiteChecker.check_all()
    
    if not prereq['requests']:
        print("  [FAIL] requests 未安装")
        results['error'] = "requests 未安装"
        return results
    
    if not prereq['playwright']:
        print("  [FAIL] playwright 不可用，尝试修复...")
        if PrerequisiteChecker.fix_playwright():
            print("  [OK] playwright 修复成功")
            prereq['playwright'] = True
        else:
            print("  [WARN] playwright 修复失败，继续执行...")
    
    print(f"  playwright: {'OK' if prereq['playwright'] else 'FAIL'}")
    print(f"  requests: {'OK' if prereq['requests'] else 'FAIL'}")
    print()
    
    # ========== 阶段 1: 目标探测 ==========
    print("[1] 目标探测")
    print("-" * 70)
    
    import requests
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    try:
        r = session.get(target, timeout=10)
        results['target_info'] = {
            'status_code': r.status_code,
            'server': r.headers.get('Server', 'N/A'),
            'content_type': r.headers.get('Content-Type', 'N/A'),
        }
        print(f"  状态码: {r.status_code}")
        print(f"  Server: {r.headers.get('Server', 'N/A')}")
        
        # 技术栈识别
        html_lower = r.text.lower()
        tech_stack = {}
        if 'vue' in html_lower: tech_stack['frontend'] = 'Vue.js'
        if 'react' in html_lower: tech_stack['frontend'] = 'React'
        if 'jquery' in html_lower: tech_stack['frontend'] = 'jQuery'
        if 'element' in html_lower: tech_stack['frontend'] = 'ElementUI'
        if 'angular' in html_lower: tech_stack['frontend'] = 'Angular'
        results['tech_stack'] = tech_stack
        print(f"  技术栈: {tech_stack}")
        
    except Exception as e:
        print(f"  [WARN] 目标探测失败: {e}")
    
    print()
    
    # ========== 阶段 2: 端点发现 ==========
    print("[2] 端点发现")
    print("-" * 70)
    
    discovery = EndpointDiscovery(target, session)
    
    # 2.1 V35JSAnalyzer
    js_endpoints = discovery.discover_v35_js_analyzer()
    results['endpoints'].extend([
        {'url': ep.url, 'method': ep.method, 'source': f'v35js_{ep.discovered_by}'}
        for ep in js_endpoints
    ])
    
    # 2.2 Swagger 发现
    swagger_urls = discovery.discover_swagger()
    results['endpoints'].extend([
        {'url': url, 'method': 'GET', 'source': 'swagger'}
        for url in swagger_urls
    ])
    
    # 2.3 智能猜测
    guessed_paths = discovery.discover_intelligent_guess()
    results['endpoints'].extend([
        {'url': target.rstrip('/') + path, 'method': 'GET', 'source': 'intelligent_guess'}
        for path in guessed_paths
    ])
    
    print(f"  端点总数: {len(results['endpoints'])}")
    print()
    
    # ========== 阶段 3: 编排执行 ==========
    if use_orchestrator:
        print("[3] 智能编排执行")
        print("-" * 70)
        
        try:
            from core.orchestrator import run_enhanced_agentic_test
            
            orch_result = run_enhanced_agentic_test(
                target=target,
                max_iterations=max_iterations,
                max_duration=max_duration,
                enable_fuzzing=enable_fuzzing,
                enable_testing=enable_testing
            )
            
            # 整合结果
            if orch_result.get('stage_results', {}).get('discovery', {}).get('data'):
                disc_data = orch_result['stage_results']['discovery']['data']
                print(f"  编排器发现: {disc_data.get('total_endpoints', 0)} 端点")
            
            if orch_result.get('stage_results', {}).get('fuzzing', {}).get('data'):
                fuzz_data = orch_result['stage_results']['fuzzing']['data']
                print(f"  Fuzzing 测试: {fuzz_data.get('tested', 0)} 目标")
            
            # 提取洞察
            if orch_result.get('insights'):
                results['insights'] = orch_result['insights'][:10]
            
        except Exception as e:
            print(f"  [WARN] 编排器执行失败: {e}")
            logger.warning(f"编排器执行失败: {e}")
    
    print()
    
    # ========== 阶段 4: 报告生成 ==========
    print("[4] 生成报告")
    print("-" * 70)
    
    duration = results.get('duration', 0)
    report = ReportGenerator.generate(results)
    
    print(report)
    
    # 保存报告
    report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"\n报告已保存: {report_file}")
    
    results['report'] = report
    results['report_file'] = report_file
    
    return results


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='API Security Testing Skill')
    parser.add_argument('target', help='目标 URL')
    parser.add_argument('--no-orchestrator', action='store_true', help='禁用编排器')
    parser.add_argument('--no-fuzzing', action='store_true', help='禁用 fuzzing')
    parser.add_argument('--no-testing', action='store_true', help='禁用漏洞测试')
    parser.add_argument('--max-iterations', type=int, default=50, help='最大迭代次数')
    
    args = parser.parse_args()
    
    # 确保目标 URL 格式正确
    target = args.target
    if not target.startswith('http'):
        target = 'http://' + target
    
    run_skill(
        target=target,
        use_orchestrator=not args.no_orchestrator,
        enable_fuzzing=not args.no_fuzzing,
        enable_testing=not args.no_testing,
        max_iterations=args.max_iterations
    )
