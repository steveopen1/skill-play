#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Storage Security Tester - 云存储安全测试模块

支持: 阿里云 OSS, 腾讯云 COS, 华为云 OBS, AWS S3, MinIO, Azure Blob

功能:
- 云存储桶发现与识别
- 公开可列目录检测
- 匿名上传/删除权限检测
- 敏感文件泄露检测
- 目录遍历检测
- CORS 配置检测
- 访问日志泄露检测

参考:
- OSS_scanner (bitboy-sys): https://github.com/bitboy-sys/OSS_scanner
- BucketTool (libaibaia): https://github.com/libaibaia/BucketTool
"""

import requests
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class CloudStorageTester:
    """云存储安全测试器"""
    
    # 云厂商 URL 模板
    CLOUD_TEMPLATES = {
        'aliyun': {
            'http': 'http://{bucket}.oss-{region}.aliyuncs.com',
            'https': 'https://{bucket}.oss-{region}.aliyuncs.com'
        },
        'tencent': {
            'http': 'http://{bucket}.cos.{region}.myqcloud.com',
            'https': 'https://{bucket}.cos.{region}.myqcloud.com'
        },
        'huawei': {
            'http': 'http://{bucket}.obs.{region}.myhwclouds.com',
            'https': 'https://{bucket}.obs.{region}.myhwclouds.com'
        },
        'aws': {
            'http': 'http://{bucket}.s3.{region}.amazonaws.com',
            'https': 'https://{bucket}.s3.{region}.amazonaws.com'
        }
    }
    
    # 敏感文件路径
    SENSITIVE_PATHS = [
        '.env', '.git/config', '.git/HEAD', 'id_rsa', 'id_rsa.pub',
        'access_key', 'secret_key', 'credentials', 'aws_key',
        '.sql', '.bak', '.backup', '.db', '.dump',
        '.pem', '.key', '.crt', '.p12', '.pfx',
        'wp-config.php', 'config.php', 'settings.py',
        'database.yml', 'credentials.json',
        'backup.sql', 'db_backup', 'data.sql',
        'passwd', 'shadow', 'hosts', 'nginx.conf',
        'httpd.conf', 'apache2.conf'
    ]
    
    # 日志路径
    LOG_PATHS = [
        '/logs/', '/log/', '/accesslog/', '/access_log/',
        '/error_log/', '/debug.log', '/app.log',
        '/analytics/', '/stats/', '/monitoring/'
    ]
    
    # 云存储 URL 识别模式
    CLOUD_PATTERNS = {
        'aliyun': [
            '.oss-', '.aliyuncs.com', 'aliyun', 'oss-cn-',
            'x-oss-', 'oss.amazonaws.com'
        ],
        'tencent': [
            '.cos.', '.myqcloud.com', 'cos.', 'cos-cn-',
            'tencent', 'gzgrid'
        ],
        'huawei': [
            '.obs.', '.myhwclouds.com', 'hw OBS', 'obs-cn-'
        ],
        'aws': [
            '.s3.', 'amazonaws.com', 'aws-s3', 's3.amazonaws.com',
            's3-external-', 's3.dualstack.'
        ],
        'minio': [
            'minio', ':9000', ':9001', 'play.minio'
        ],
        'azure': [
            '.blob.core.', 'windows.net', 'azure'
        ]
    }
    
    # XML 响应中的列表标记
    LIST_PATTERNS = [
        '<ListBucketResult', '<ListAllMyBucketsResult',
        'ListBucketResponse', '<?xml version'
    ]

    def __init__(self, session: requests.Session = None):
        """初始化云存储测试器"""
        self.session = session or requests.Session()
        self.findings: List[Dict] = []
    
    def detect_cloud_provider(self, url: str) -> Optional[str]:
        """检测云厂商类型"""
        url_lower = url.lower()
        for provider, patterns in self.CLOUD_PATTERNS.items():
            for pattern in patterns:
                if pattern in url_lower:
                    return provider
        return None
    
    def test_public_listing(self, bucket_url: str) -> Tuple[bool, str]:
        """测试公开可列目录"""
        try:
            resp = self.session.get(bucket_url, timeout=10)
            
            # 检查是否返回 XML 文件列表
            if resp.status_code == 200:
                content = resp.text
                for pattern in self.LIST_PATTERNS:
                    if pattern in content:
                        # 解析 XML 获取文件列表
                        try:
                            root = ET.fromstring(content)
                            files = []
                            for elem in root.iter():
                                if elem.tag.endswith('Key'):
                                    files.append(elem.text)
                            if files:
                                return True, f"公开可列目录 - 找到 {len(files)} 个文件"
                            return True, f"公开可列目录 - 返回 XML 格式列表 ({len(content)} bytes)"
                        except:
                            return True, f"公开可列目录 - 返回 XML 内容 ({len(content)} bytes)"
            
            # 检查是否返回 AccessDenied
            if 'AccessDenied' in resp.text or resp.status_code == 403:
                return False, "正确拒绝 (403)"
            
            if resp.status_code == 404:
                return False, "资源不存在 (404)"
                
            return False, f"状态码: {resp.status_code}"
            
        except requests.exceptions.Timeout:
            return False, "请求超时"
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_anonymous_put(self, bucket_url: str) -> Tuple[bool, str]:
        """测试匿名 PUT 上传"""
        import time
        test_content = f"OSS_TEST_{time.time()}"
        test_key = f"test_{int(time.time())}.txt"
        
        try:
            resp = self.session.put(
                f"{bucket_url}/{test_key}",
                data=test_content,
                timeout=10
            )
            
            if resp.status_code in [200, 201]:
                # 尝试删除测试文件
                try:
                    self.session.delete(f"{bucket_url}/{test_key}", timeout=10)
                except:
                    pass
                return True, f"可匿名上传 (状态码: {resp.status_code})"
            
            return False, f"PUT 上传失败 (状态码: {resp.status_code})"
            
        except requests.exceptions.Timeout:
            return False, "PUT 请求超时"
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_anonymous_post(self, bucket_url: str) -> Tuple[bool, str]:
        """测试匿名 POST 表单上传"""
        import time
        test_content = f"OSS_TEST_{time.time()}"
        
        try:
            files = {'file': ('test.txt', test_content, 'text/plain')}
            resp = self.session.post(bucket_url, files=files, timeout=10)
            
            if resp.status_code in [200, 201]:
                return True, f"可匿名 POST 上传 (状态码: {resp.status_code})"
            
            return False, f"POST 上传失败 (状态码: {resp.status_code})"
            
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_anonymous_delete(self, bucket_url: str) -> Tuple[bool, str]:
        """测试匿名 DELETE 权限"""
        import time
        test_key = f"test_del_{int(time.time())}.txt"
        
        try:
            # 先上传测试文件
            self.session.put(
                f"{bucket_url}/{test_key}",
                data="test",
                timeout=10
            )
            
            # 尝试删除
            resp = self.session.delete(f"{bucket_url}/{test_key}", timeout=10)
            
            if resp.status_code in [200, 204]:
                return True, f"可匿名删除 (状态码: {resp.status_code})"
            
            return False, f"DELETE 失败 (状态码: {resp.status_code})"
            
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_sensitive_files(self, bucket_url: str) -> Tuple[bool, List[str]]:
        """测试敏感文件泄露"""
        found = []
        
        for path in self.SENSITIVE_PATHS:
            try:
                resp = self.session.get(f"{bucket_url}/{path}", timeout=10)
                
                if resp.status_code == 200 and len(resp.content) > 0:
                    content = resp.text[:500].lower()
                    # 检查是否包含敏感关键词
                    sensitive_keywords = [
                        'password', 'secret', 'aws_access', 'aws_secret',
                        'api_key', 'api-key', 'token', 'private_key',
                        '-----begin', 'begin rsa', 'begin ecdsa',
                        'database', 'db_password', 'mysql'
                    ]
                    
                    if any(kw in content for kw in sensitive_keywords):
                        found.append(f"{path} (包含敏感信息)")
                    elif len(resp.content) > 100:
                        found.append(f"{path} ({len(resp.content)} bytes)")
                        
            except:
                pass
        
        return len(found) > 0, found[:10]  # 最多返回10个
    
    def test_directory_traversal(self, bucket_url: str) -> Tuple[bool, str]:
        """测试目录遍历"""
        traversal_paths = [
            '../../etc/passwd',
            '../../../etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '....//....//etc/passwd',
            '..././..././etc/passwd'
        ]
        
        for path in traversal_paths:
            try:
                resp = self.session.get(f"{bucket_url}/{path}", timeout=10)
                
                if resp.status_code == 200:
                    content = resp.text[:200]
                    if 'root:' in content or 'Administrator' in content:
                        return True, f"目录遍历成功 - 读取了系统文件"
                    elif len(resp.text) > 50 and not 'AccessDenied' in resp.text:
                        return True, f"可能存在目录遍历 (路径: {path})"
                        
            except:
                pass
        
        return False, "未发现目录遍历"
    
    def test_cors_misconfiguration(self, bucket_url: str) -> Tuple[bool, str]:
        """测试 CORS 配置过宽"""
        try:
            resp = self.session.options(
                bucket_url,
                headers={
                    'Origin': 'http://evil.com',
                    'Access-Control-Request-Method': 'PUT'
                },
                timeout=10
            )
            
            allow_origin = resp.headers.get('Access-Control-Allow-Origin', '')
            allow_methods = resp.headers.get('Access-Control-Allow-Methods', '')
            allow_credentials = resp.headers.get('Access-Control-Allow-Credentials', '')
            
            if allow_origin == '*':
                if 'PUT' in allow_methods or 'POST' in allow_methods:
                    return True, f"CORS 严重过宽 - Origin:*, Methods: {allow_methods}"
                return True, f"CORS 允许任意 Origin: {allow_origin}"
            
            if 'http://evil.com' in allow_origin:
                if allow_credentials.lower() == 'true':
                    return True, f"CORS 可利用 - Origin: http://evil.com, Credentials: true, Methods: {allow_methods}"
                return True, f"CORS 允许特定恶意 Origin: {allow_origin}"
            
            return False, f"CORS 配置正常"
            
        except Exception as e:
            return False, f"CORS 检测失败: {e}"
    
    def test_log_exposure(self, bucket_url: str) -> Tuple[bool, List[str]]:
        """测试访问日志泄露"""
        found = []
        
        for log_path in self.LOG_PATHS:
            try:
                resp = self.session.get(f"{bucket_url}/{log_path}", timeout=10)
                
                if resp.status_code == 200 and len(resp.content) > 100:
                    found.append(f"{log_path} ({len(resp.content)} bytes)")
                    
            except:
                pass
        
        return len(found) > 0, found[:5]
    
    def test_version_exposure(self, bucket_url: str) -> Tuple[bool, List[str]]:
        """测试版本控制泄露"""
        found = []
        version_paths = [
            '?versions', '?versioning', '/.versions/',
            '/_version/', '/versions/', '?uploads'
        ]
        
        for path in version_paths:
            try:
                resp = self.session.get(f"{bucket_url}/{path}", timeout=10)
                
                if resp.status_code == 200 and 'version' in resp.text.lower():
                    found.append(f"{path}")
                    
            except:
                pass
        
        return len(found) > 0, found
    
    def test_acl_public(self, bucket_url: str) -> Tuple[bool, str]:
        """测试 ACL 公共权限"""
        try:
            resp = self.session.get(f"{bucket_url}?acl", timeout=10)
            
            if resp.status_code == 200:
                content = resp.text
                if 'AllUsers' in content or 'AuthenticatedUsers' in content:
                    return True, f"ACL 配置为公共访问"
                if '<Grant>' in content and 'FULL_CONTROL' in content:
                    return True, "ACL 存在完全控制权限"
            
            return False, "ACL 检查未发现明显问题"
            
        except Exception as e:
            return False, f"ACL 检测失败: {e}"
    
    def full_test(self, bucket_url: str, provider: str = None) -> List[Dict]:
        """执行完整云存储安全测试"""
        print(f"[CloudStorage] 开始测试: {bucket_url}")
        
        if not provider:
            provider = self.detect_cloud_provider(bucket_url)
        print(f"[CloudStorage] 识别厂商: {provider or '未知'}")
        
        results = []
        
        # 1. 公开可列目录
        print("[CloudStorage] [1/8] 测试公开可列目录...")
        is_public, msg = self.test_public_listing(bucket_url)
        if is_public:
            results.append({
                'type': 'Public Listing',
                'severity': 'Critical',
                'evidence': msg,
                'url': bucket_url,
                'provider': provider
            })
        
        # 2. 匿名 PUT
        print("[CloudStorage] [2/8] 测试匿名 PUT 上传...")
        can_put, msg = self.test_anonymous_put(bucket_url)
        if can_put:
            results.append({
                'type': 'Anonymous PUT Upload',
                'severity': 'Critical',
                'evidence': msg,
                'url': bucket_url,
                'provider': provider
            })
        
        # 3. 敏感文件
        print("[CloudStorage] [3/8] 测试敏感文件泄露...")
        has_sensitive, files = self.test_sensitive_files(bucket_url)
        if has_sensitive:
            results.append({
                'type': 'Sensitive File Exposure',
                'severity': 'Critical',
                'evidence': ', '.join(files),
                'url': bucket_url,
                'provider': provider
            })
        
        # 4. 目录遍历
        print("[CloudStorage] [4/8] 测试目录遍历...")
        can_traverse, msg = self.test_directory_traversal(bucket_url)
        if can_traverse:
            results.append({
                'type': 'Directory Traversal',
                'severity': 'High',
                'evidence': msg,
                'url': bucket_url,
                'provider': provider
            })
        
        # 5. CORS
        print("[CloudStorage] [5/8] 测试 CORS...")
        cors_vuln, msg = self.test_cors_misconfiguration(bucket_url)
        if cors_vuln:
            results.append({
                'type': 'CORS Misconfiguration',
                'severity': 'High',
                'evidence': msg,
                'url': bucket_url,
                'provider': provider
            })
        
        # 6. 日志泄露
        print("[CloudStorage] [6/8] 测试日志泄露...")
        has_logs, log_files = self.test_log_exposure(bucket_url)
        if has_logs:
            results.append({
                'type': 'Log Exposure',
                'severity': 'Medium',
                'evidence': ', '.join(log_files),
                'url': bucket_url,
                'provider': provider
            })
        
        # 7. 版本控制
        print("[CloudStorage] [7/8] 测试版本控制泄露...")
        has_versions, version_paths = self.test_version_exposure(bucket_url)
        if has_versions:
            results.append({
                'type': 'Version Control Exposure',
                'severity': 'Medium',
                'evidence': ', '.join(version_paths),
                'url': bucket_url,
                'provider': provider
            })
        
        # 8. ACL 检查
        print("[CloudStorage] [8/8] 测试 ACL 配置...")
        acl_issue, msg = self.test_acl_public(bucket_url)
        if acl_issue:
            results.append({
                'type': 'ACL Public Access',
                'severity': 'High',
                'evidence': msg,
                'url': bucket_url,
                'provider': provider
            })
        
        print(f"[CloudStorage] 测试完成，发现 {len(results)} 个问题")
        return results
    
    def test_from_js_or_response(self, text: str) -> List[str]:
        """从 JS 或响应文本中发现存储桶 URL"""
        import re
        urls = []
        
        # 阿里云 OSS
        aliyun_patterns = [
            r'https?://[a-zA-Z0-9.-]+\.oss-[a-zA-Z0-9-]+\.aliyuncs\.com[^\s"\'<>]*',
            r'https?://[a-zA-Z0-9.-]+\.oss\.aliyuncs\.com[^\s"\'<>]*',
        ]
        
        # 腾讯云 COS
        tencent_patterns = [
            r'https?://[a-zA-Z0-9.-]+\.cos\.[a-zA-Z0-9.-]+\.myqcloud\.com[^\s"\'<>]*',
            r'https?://[a-zA-Z0-9.-]+\.cos\.myqcloud\.com[^\s"\'<>]*',
        ]
        
        # AWS S3
        aws_patterns = [
            r'https?://[a-zA-Z0-9.-]+\.s3\.[a-zA-Z0-9.-]+\.amazonaws\.com[^\s"\'<>]*',
            r'https?://s3\.[a-zA-Z0-9.-]+\.amazonaws\.com/[^\s"\'<>]*',
        ]
        
        all_patterns = aliyun_patterns + tencent_patterns + aws_patterns
        
        for pattern in all_patterns:
            matches = re.findall(pattern, text)
            urls.extend(matches)
        
        return list(set(urls))


def discover_and_test_cloud_storage(target: str, api_base: str = None) -> List[Dict]:
    """发现并测试云存储"""
    print(f"[CloudStorage] 开始云存储安全检测，目标: {target}")
    
    tester = CloudStorageTester()
    all_findings = []
    
    # 从 API 响应中发现存储桶 URL
    if api_base:
        try:
            resp = requests.get(api_base, timeout=10)
            urls = tester.test_from_js_or_response(resp.text)
            print(f"[CloudStorage] 从响应中发现 {len(urls)} 个候选 URL")
            
            for url in urls:
                print(f"[CloudStorage] 测试: {url}")
                results = tester.full_test(url)
                all_findings.extend(results)
        except Exception as e:
            print(f"[CloudStorage] 响应分析失败: {e}")
    
    return all_findings


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python cloud_storage_tester.py <bucket_url>")
        print("Example: python cloud_storage_tester.py http://test.oss-cn-region.aliyuncs.com")
        sys.exit(1)
    
    bucket_url = sys.argv[1]
    tester = CloudStorageTester()
    results = tester.full_test(bucket_url)
    
    print("\n" + "="*60)
    print("云存储安全测试结果")
    print("="*60)
    
    for i, r in enumerate(results, 1):
        print(f"\n[{i}] {r['type']}")
        print(f"    Severity: {r['severity']}")
        print(f"    Evidence: {r['evidence']}")
        print(f"    URL: {r['url']}")
