# API 接口渗透测试自动化脚本
# 作为 skill 使用：skill security-testing scan --target <url>

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class APITester:
    """API 渗透测试引擎"""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.results = []
        self.baseline = None
        self.context = {
            'stage': 'discovery',
            'endpoints': [],
            'auth_tokens': {},
            'waf_detected': False
        }
        
        # 设置 User-Agent
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityTesting/2.0)',
            'Accept': '*/*'
        })
    
    def load_payloads(self, vuln_type: str) -> List[Dict]:
        """加载指定类型的 payload"""
        try:
            with open(f'payloads/{vuln_type}.json', 'r') as f:
                data = json.load(f)
                return data.get('payloads', [])
        except FileNotFoundError:
            print(f"[!] Payload file not found: {vuln_type}.json")
            return []
    
    def send_request(self, url: str, method: str = 'GET', params: Dict = None, 
                     data: Dict = None, headers: Dict = None) -> requests.Response:
        """发送 HTTP 请求"""
        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=data,
                headers=headers,
                timeout=self.config.get('timeout', 30)
            )
            return response
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
            return None
    
    def set_baseline(self, response: requests.Response):
        """设置正常响应基线"""
        self.baseline = {
            'status_code': response.status_code,
            'content_length': len(response.content),
            'content_hash': hash(response.text),
            'response_time': response.elapsed.total_seconds()
        }
    
    def analyze_response(self, response: requests.Response) -> str:
        """分析响应，判断是否存在漏洞"""
        if not response:
            return 'error'
        
        # WAF 检测
        waf_indicators = ['waf', '360', 'aliyun', 'tencent', 'cloudflare']
        for indicator in waf_indicators:
            if indicator in response.text.lower():
                self.context['waf_detected'] = True
                return 'waf_detected'
        
        # 认证检测
        if response.status_code in [401, 403] or 'login' in response.url.lower():
            return 'auth_required'
        
        # 速率限制检测
        if response.status_code == 429:
            return 'rate_limited'
        
        # 基线对比
        if self.baseline:
            if response.status_code != self.baseline['status_code']:
                return 'status_changed'
            if abs(len(response.content) - self.baseline['content_length']) > 100:
                return 'content_changed'
        
        return 'normal'
    
    def test_sqli(self, endpoint: str, param: str = 'id'):
        """SQL 注入测试"""
        print(f"\n[*] Testing SQL injection on {endpoint}")
        payloads = self.load_payloads('sqli')
        vulns = []
        
        for payload in payloads:
            test_url = f"{self.target}{endpoint}"
            params = {param: payload['payload']}
            
            response = self.send_request(test_url, params=params)
            result = self.analyze_response(response)
            
            if result in ['status_changed', 'content_changed', 'waf_detected']:
                vuln = {
                    'type': 'sqli',
                    'endpoint': endpoint,
                    'param': param,
                    'payload': payload['payload'],
                    'payload_name': payload['name'],
                    'response_status': result,
                    'status_code': response.status_code if response else 0,
                    'timestamp': datetime.now().isoformat()
                }
                vulns.append(vuln)
                print(f"  [+] Potential SQLi found: {payload['name']}")
            
            # 速率限制
            time.sleep(self.config.get('delay', 0.1))
        
        self.results.extend(vulns)
        return vulns
    
    def test_xss(self, endpoint: str, param: str = 'q'):
        """XSS 测试"""
        print(f"\n[*] Testing XSS on {endpoint}")
        payloads = self.load_payloads('xss')
        vulns = []
        
        for payload in payloads:
            test_url = f"{self.target}{endpoint}"
            params = {param: payload['payload']}
            
            response = self.send_request(test_url, params=params)
            
            # 检查 payload 是否被反射
            if response and payload['payload'] in response.text:
                vuln = {
                    'type': 'xss',
                    'endpoint': endpoint,
                    'param': param,
                    'payload': payload['payload'],
                    'payload_name': payload['name'],
                    'reflected': True,
                    'timestamp': datetime.now().isoformat()
                }
                vulns.append(vuln)
                print(f"  [+] Potential XSS found: {payload['name']} (reflected)")
            
            time.sleep(self.config.get('delay', 0.1))
        
        self.results.extend(vulns)
        return vulns
    
    def test_auth_bypass(self, endpoints: List[str]):
        """认证绕过测试"""
        print(f"\n[*] Testing authentication bypass")
        bypass_techniques = [
            {'path_traversal': '../'},
            {'parameter_pollution': ';'},
            {'header_injection': {'X-Original-URL': '/admin'}},
            {'method_switch': 'OPTIONS'}
        ]
        
        for endpoint in endpoints:
            for technique in bypass_techniques:
                for tech_name, tech_value in technique.items():
                    test_url = f"{self.target}{endpoint}"
                    
                    if tech_name == 'header_injection':
                        response = self.send_request(test_url, headers=tech_value)
                    elif tech_name == 'method_switch':
                        response = self.send_request(test_url, method=tech_value)
                    else:
                        response = self.send_request(f"{test_url}{tech_value}")
                    
                    result = self.analyze_response(response)
                    if result == 'status_changed':
                        print(f"  [+] Potential auth bypass: {endpoint} via {tech_name}")
                    
                    time.sleep(self.config.get('delay', 0.1))
    
    def discover_endpoints(self) -> List[str]:
        """发现 API 端点"""
        print(f"\n[*] Discovering endpoints for {self.target}")
        common_endpoints = [
            '/api', '/api/v1', '/api/v2', '/rest', '/rest/api',
            '/service', '/services', '/ws', '/WebService',
            '/admin', '/manage', '/manager', '/system',
            '/login', '/logout', '/auth', '/oauth',
            '/user', '/users', '/account', '/profile',
            '/config', '/configs', '/settings', '/application'
        ]
        
        found = []
        for endpoint in common_endpoints:
            test_url = f"{self.target}{endpoint}"
            response = self.send_request(test_url)
            
            if response and response.status_code not in [404]:
                found.append(endpoint)
                print(f"  [+] Found: {endpoint} ({response.status_code})")
            
            time.sleep(self.config.get('delay', 0.05))
        
        self.context['endpoints'] = found
        return found
    
    def generate_report(self, output_format: str = 'markdown') -> str:
        """生成测试报告"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 统计漏洞
        sqli_count = len([r for r in self.results if r['type'] == 'sqli'])
        xss_count = len([r for r in self.results if r['type'] == 'xss'])
        
        if output_format == 'markdown':
            report = f"""# API 渗透测试报告

## 执行摘要
- **测试目标**: {self.target}
- **测试时间**: {timestamp}
- **发现端点数**: {len(self.context['endpoints'])}

## 漏洞统计
- SQL 注入：{sqli_count}
- XSS: {xss_count}
- **总计**: {len(self.results)}

## 详细结果

### SQL 注入
"""
            for vuln in [r for r in self.results if r['type'] == 'sqli']:
                report += f"- **{vuln['endpoint']}** (`{vuln['param']}`): {vuln['payload_name']}\n"
                report += f"  - Payload: `{vuln['payload']}`\n"
                report += f"  - 响应状态：{vuln['response_status']}\n\n"
            
            report += "### XSS\n"
            for vuln in [r for r in self.results if r['type'] == 'xss']:
                report += f"- **{vuln['endpoint']}** (`{vuln['param']}`): {vuln['payload_name']}\n"
                report += f"  - Payload: `{vuln['payload']}`\n"
                report += f"  - 已反射：{vuln.get('reflected', False)}\n\n"
            
            return report
        
        elif output_format == 'json':
            return json.dumps({
                'target': self.target,
                'timestamp': timestamp,
                'endpoints_found': len(self.context['endpoints']),
                'vulnerabilities': self.results,
                'summary': {
                    'sqli': sqli_count,
                    'xss': xss_count,
                    'total': len(self.results)
                }
            }, indent=2)
        
        return ""
    
    def run_full_scan(self):
        """执行完整扫描"""
        print(f"\n{'='*60}")
        print(f"API 渗透测试 - {self.target}")
        print(f"{'='*60}\n")
        
        # 阶段 1: 信息收集
        self.context['stage'] = 'discovery'
        endpoints = self.discover_endpoints()
        
        if not endpoints:
            print("[!] No endpoints found, exiting...")
            return
        
        # 设置基线
        baseline_url = f"{self.target}{endpoints[0]}"
        baseline_response = self.send_request(baseline_url)
        if baseline_response:
            self.set_baseline(baseline_response)
        
        # 阶段 2: SQL 注入测试
        self.context['stage'] = 'vulnerability'
        for endpoint in endpoints[:5]:  # 限制测试前 5 个端点
            self.test_sqli(endpoint)
        
        # 阶段 3: XSS 测试
        for endpoint in endpoints[:5]:
            self.test_xss(endpoint)
        
        # 阶段 4: 生成报告
        self.context['stage'] = 'reporting'
        report = self.generate_report('markdown')
        
        # 保存报告
        with open(f"reports/{self.target.replace('://', '_').replace('/', '_')}_report.md", 'w') as f:
            f.write(report)
        
        print(f"\n{'='*60}")
        print(f"测试完成！发现 {len(self.results)} 个潜在漏洞")
        print(f"报告已保存到 reports/ 目录")
        print(f"{'='*60}\n")
        
        return self.results


# Skill 入口函数
def skill_main(args: Dict):
    """Skill 主入口"""
    target = args.get('target')
    test_type = args.get('type', 'full')
    output = args.get('output', 'markdown')
    
    if not target:
        return {"error": "Missing required parameter: target"}
    
    config = {
        'timeout': args.get('timeout', 30),
        'delay': args.get('delay', 0.1),
        'threads': args.get('threads', 1)
    }
    
    tester = APITester(target, config)
    
    if test_type == 'sqli':
        endpoint = args.get('endpoint', '/api/user')
        param = args.get('param', 'id')
        results = tester.test_sqli(endpoint, param)
    elif test_type == 'xss':
        endpoint = args.get('endpoint', '/search')
        param = args.get('param', 'q')
        results = tester.test_xss(endpoint, param)
    elif test_type == 'full':
        results = tester.run_full_scan()
    else:
        return {"error": f"Unknown test type: {test_type}"}
    
    return {
        "target": target,
        "test_type": test_type,
        "vulnerabilities_found": len(results),
        "results": results,
        "report": tester.generate_report(output)
    }


# CLI 入口
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python api_tester.py <target> [type]")
        print("  target: Target URL (e.g., https://target.com)")
        print("  type: Test type (full|sqli|xss|auth)")
        sys.exit(1)
    
    target = sys.argv[1]
    test_type = sys.argv[2] if len(sys.argv) > 2 else 'full'
    
    result = skill_main({'target': target, 'type': test_type})
    print(json.dumps(result, indent=2))
