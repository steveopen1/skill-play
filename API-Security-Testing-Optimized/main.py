#!/usr/bin/env python3
"""
API Security Testing Skill - Main Entry Point

用法:
    python main.py <target_url> [options]
    
示例:
    python main.py http://49.65.100.160:6004
    python main.py http://49.65.100.160:6004 --no-browser
    python main.py http://49.65.100.160:6004 --output report.json
"""

import sys
import argparse
import json
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description='API Security Testing Skill - Agent驱动的自动化API渗透测试',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s http://49.65.100.160:6004
  %(prog)s http://49.65.100.160:6004 --no-browser
  %(prog)s http://49.65.100.160:6004 --output report.json --format json
        """
    )
    
    parser.add_argument('target', help='目标 URL')
    parser.add_argument('--no-browser', action='store_true', 
                        help='禁用无头浏览器采集')
    parser.add_argument('--output', '-o', default=None,
                        help='输出报告路径')
    parser.add_argument('--format', '-f', choices=['json', 'markdown', 'text'], 
                        default='text', help='输出格式')
    parser.add_argument('--max-iterations', type=int, default=100,
                        help='最大迭代次数 (默认: 100)')
    parser.add_argument('--max-duration', type=float, default=3600,
                        help='最大运行时长秒数 (默认: 3600)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='详细输出')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        from scripts import EnhancedAgenticOrchestrator
        
        print("=" * 70)
        print(" API Security Testing Skill v3.0")
        print("=" * 70)
        print(f"目标: {args.target}")
        print(f"无头浏览器: {'禁用' if args.no_browser else '启用'}")
        print("=" * 70)
        
        orch = EnhancedAgenticOrchestrator(
            args.target,
            use_browser=not args.no_browser
        )
        
        result = orch.execute(
            max_iterations=args.max_iterations,
            max_duration=args.max_duration,
            enable_fuzzing=True,
            enable_testing=True
        )
        
        if args.output:
            if args.format == 'json':
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False, default=str)
            elif args.format == 'markdown':
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(generate_markdown_report(result))
            else:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(generate_text_report(result))
            print(f"\n报告已保存: {args.output}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n[!] 用户中断")
        return 130
    except Exception as e:
        logger.error(f"执行失败: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def generate_markdown_report(result: dict) -> str:
    """生成 Markdown 报告"""
    md = "# API 安全渗透测试报告\n\n"
    md += f"**扫描时间**: {result.get('timestamp', datetime.now().isoformat())}\n\n"
    
    if 'summary' in result:
        md += "## 执行摘要\n\n"
        for key, value in result['summary'].items():
            md += f"- **{key}**: {value}\n"
        md += "\n"
    
    if 'vulnerabilities' in result and result['vulnerabilities']:
        md += "## 漏洞发现\n\n"
        for vuln in result['vulnerabilities']:
            md += f"### {vuln.get('type', 'Unknown')}\n\n"
            md += f"- **严重程度**: {vuln.get('severity', 'Unknown')}\n"
            md += f"- **端点**: {vuln.get('endpoint', 'Unknown')}\n"
            md += f"- **置信度**: {vuln.get('confidence', 0) * 100:.0f}%\n\n"
    
    return md


def generate_text_report(result: dict) -> str:
    """生成纯文本报告"""
    text = "=" * 70 + "\n"
    text += " API 安全渗透测试报告\n"
    text += "=" * 70 + "\n\n"
    
    if 'summary' in result:
        text += "执行摘要:\n"
        for key, value in result['summary'].items():
            text += f"  {key}: {value}\n"
        text += "\n"
    
    return text


if __name__ == "__main__":
    sys.exit(main())
