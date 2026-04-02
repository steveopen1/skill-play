#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API Security Testing Skill - 一键执行入口

用法:
    python3 run_skill.py http://target.com

或者导入使用:
    from run_skill import run_security_test
    result = run_security_test('http://target.com')
"""

import sys
import json
import time
from datetime import datetime
from typing import Dict, Optional

# 添加 core 目录到路径
sys.path.insert(0, '/workspace/skill-play/API-Security-Testing-Optimized')


def print_banner():
    print("=" * 70)
    print("  API Security Testing Skill - 自动化渗透测试")
    print("=" * 70)
    print()


def check_prerequisites() -> bool:
    """检查前置依赖"""
    print("[0] 前置检查")
    print("-" * 70)
    
    errors = []
    
    # 检查 playwright
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        print("  [OK] playwright chromium 可用")
    except Exception as e:
        errors.append(f"playwright: {e}")
        print(f"  [FAIL] playwright: {e}")
        
        # 尝试自动修复
        print("  [TRY] 尝试安装依赖...")
        import subprocess
        try:
            subprocess.run(['playwright', 'install-deps', 'chromium'], 
                          capture_output=True, timeout=120)
            subprocess.run(['playwright', 'install', 'chromium'], 
                          capture_output=True, timeout=120)
            
            # 重新验证
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                browser.close()
            print("  [OK] playwright 修复成功")
            errors.clear()
        except Exception as e2:
            errors.append(f"playwright 修复失败: {e2}")
    
    # 检查 requests
    try:
        import requests
        print("  [OK] requests 可用")
    except ImportError:
        errors.append("requests 未安装")
        print("  [FAIL] requests 未安装")
    
    print()
    
    if errors:
        print("[FATAL] 前置检查失败:")
        for e in errors:
            print(f"  - {e}")
        return False
    
    return True


def run_with_orchestrator(target: str) -> Dict:
    """使用编排器运行测试"""
    print("[1] 使用智能编排器执行测试")
    print("-" * 70)
    
    try:
        from core.orchestrator import run_enhanced_agentic_test
        
        print(f"  目标: {target}")
        print(f"  开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        result = run_enhanced_agentic_test(
            target=target,
            max_iterations=50,
            max_duration=1800  # 30分钟
        )
        
        print()
        print("  [完成] 编排器执行完毕")
        return result
        
    except ImportError as e:
        print(f"  [WARN] 编排器导入失败: {e}")
        print("  [INFO] 回退到基础测试模式")
        return None


def run_fallback_test(target: str) -> Dict:
    """回退到基础测试"""
    print("[2] 基础测试模式")
    print("-" * 70)
    
    from core.deep_api_tester_v55 import DeepAPITesterV55
    from core.browser_tester import BrowserAutomationTester, BrowserEngine, BrowserTestConfig
    
    results = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'endpoints': [],
        'vulnerabilities': [],
        'info': []
    }
    
    # 初始化测试器
    print("  [初始化] DeepAPITesterV55")
    tester = DeepAPITesterV55(target=target, headless=True)
    
    # 尝试运行测试
    print("  [执行] 运行测试...")
    try:
        tester.run_test()
        results['endpoints'] = [
            {'url': ep.url, 'method': ep.method} 
            for ep in tester.endpoints
        ]
        results['vulnerabilities'] = [
            {'type': v.type, 'severity': v.severity, 'endpoint': v.endpoint}
            for v in tester.vulnerabilities
        ]
    except Exception as e:
        print(f"  [WARN] 测试执行异常: {e}")
        results['info'].append(f"测试执行异常: {e}")
    
    return results


def generate_report(results: Dict) -> str:
    """生成测试报告"""
    report = []
    report.append("# API 安全测试报告")
    report.append("")
    report.append(f"**目标**: {results.get('target', 'N/A')}")
    report.append(f"**时间**: {results.get('timestamp', 'N/A')}")
    report.append("")
    
    report.append("## 发现统计")
    report.append("")
    report.append(f"- API 端点: {len(results.get('endpoints', []))}")
    report.append(f"- 漏洞: {len(results.get('vulnerabilities', []))}")
    report.append("")
    
    if results.get('vulnerabilities'):
        report.append("## 漏洞详情")
        report.append("")
        for v in results['vulnerabilities']:
            report.append(f"### {v.get('type', 'Unknown')}")
            report.append(f"- 严重程度: {v.get('severity', 'N/A')}")
            report.append(f"- 端点: {v.get('endpoint', 'N/A')}")
            report.append("")
    
    if results.get('info'):
        report.append("## 备注")
        report.append("")
        for info in results['info']:
            report.append(f"- {info}")
        report.append("")
    
    return "\n".join(report)


def run_security_test(target: str, use_orchestrator: bool = True) -> Dict:
    """
    运行安全测试的主函数
    
    Args:
        target: 目标 URL
        use_orchestrator: 是否优先使用编排器
    
    Returns:
        测试结果字典
    """
    print_banner()
    
    # 前置检查
    if not check_prerequisites():
        print("[FATAL] 前置检查失败，退出")
        sys.exit(1)
    
    # 执行测试
    start_time = time.time()
    
    if use_orchestrator:
        results = run_with_orchestrator(target)
    
    if results is None:
        results = run_fallback_test(target)
    
    duration = time.time() - start_time
    
    # 生成报告
    print()
    print("[FINAL] 生成报告")
    print("-" * 70)
    report = generate_report(results)
    print(report)
    
    # 保存报告
    report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"\n报告已保存: {report_file}")
    
    results['duration'] = duration
    results['report_file'] = report_file
    
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python3 run_skill.py <target_url>")
        print("示例: python3 run_skill.py http://58.215.18.57:91")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # 确保目标 URL 格式正确
    if not target.startswith('http'):
        target = 'http://' + target
    
    run_security_test(target)
