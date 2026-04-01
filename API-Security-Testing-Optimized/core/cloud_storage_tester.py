#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Storage Security Tester - 云存储安全测试模块

支持: 阿里云 OSS, 腾讯云 COS, 华为云 OBS, AWS S3, MinIO, Azure Blob

智能识别逻辑:
1. URL 模式识别 - 域名/路径特征
2. 响应头识别 - X-OSS-, X-Amz-, 特定 header
3. 响应内容识别 - XML 格式、API 字段
4. 路径模式识别 - /minio/, /bucket/, /file/ 等

参考:
- OSS_scanner (bitboy-sys): https://github.com/bitboy-sys/OSS_scanner
- BucketTool (libaibaia): https://github.com/libaibaia/BucketTool
"""

import requests
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
import re
import logging

logger = logging.getLogger(__name__)


class CloudStorageTester:
    """云存储安全测试器"""
    
    # ========== 识别模式 ==========
    
    # URL 域名模式
    DOMAIN_PATTERNS = {
        'aliyun': [
            r'\.oss-[a-zA-Z0-9-]+\.aliyuncs\.com',
            r'\.oss\.aliyuncs\.com',
            r'oss-[a-zA-Z0-9-]+-internal',
        ],
        'tencent': [
            r'\.cos\.[a-zA-Z0-9-]+\.myqcloud\.com',
            r'\.cos\.myqcloud\.com',
            r'\.cos\.tencent\.com',
        ],
        'huawei': [
            r'\.obs\.[a-zA-Z0-9-]+\.myhwclouds\.com',
            r'\.obs\.myhwclouds\.com',
            r'\.obs\.cn-north-1\.myhwclouds\.com',
        ],
        'aws': [
            r'\.s3\.[a-zA-Z0-9-]+\.amazonaws\.com',
            r'\.s3\.amazonaws\.com',
            r's3-[a-zA-Z0-9-]+\.amazonaws\.com',
        ],
        'minio': [
            r'minio',
            r':9000',
            r':9001',
            r'play\.minio\.io',
        ],
        'azure': [
            r'\.blob\.core\.[a-zA-Z0-9.]+\.microsoft\.com',
            r'\.blob\.core\.windows\.net',
        ]
    }
    
    # URL 路径模式 (当域名不是标准云存储域名时使用)
    PATH_PATTERNS = {
        'minio': [
            r'/minio/',
            r'/minio-api/',
            r'/api/s3/',
            r'/bucket/',
            r'/newbucket/',
        ],
        'oss': [
            r'/oss/',
            r'/aliyun/',
            r'/aliyunoss/',
        ],
        'cos': [
            r'/cos/',
            r'/tencentcos/',
        ],
        's3': [
            r'/s3/',
            r'/aws-s3/',
            r'/s3-api/',
        ],
        'file': [
            r'/file/',
            r'/files/',
            r'/upload/',
            r'/uploads/',
            r'/storage/',
            r'/storages/',
        ]
    }
    
    # 响应 Header 模式
    HEADER_PATTERNS = {
        'aliyun': [
            'x-oss-',
            'x-oss-meta-',
            'x-oss-request-id',
            'x-oss-server-time',
        ],
        'tencent': [
            'x-cos-',
            'x-cos-meta-',
            'x-cos-request-id',
        ],
        'huawei': [
            'x-obs-',
            'x-obs-meta-',
            'x-obs-request-id',
        ],
        'aws': [
            'x-amz-',
            'x-amz-meta-',
            'x-amz-request-id',
            'x-amz-id-2',
        ],
        'minio': [
            'x-minio-',
            'x-minio-deployment-id',
            'x-minio-zone',
            'minio-ext',
        ],
        'azure': [
            'x-ms-',
            'x-ms-request-id',
            'x-ms-blob',
        ]
    }
    
    # 响应内容 XML 模式
    XML_PATTERNS = [
        '<ListBucketResult',
        '<ListAllMyBucketsResult',
        '<ListBucketResponse',
        '<CreateBucketConfiguration',
        '<AccessControlPolicy',
        '<?xml version',
        '<LocationConstraint',
        '<Bucket>',
    ]
    
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
    
    def __init__(self, session: requests.Session = None):
        """初始化云存储测试器"""
        self.session = session or requests.Session()
        self.findings: List[Dict] = []
    
    def detect_storage_from_url(self, url: str) -> Optional[str]:
        """从 URL 模式识别存储类型"""
        url_lower = url.lower()
        
        # 1. 检查域名模式
        for storage_type, patterns in self.DOMAIN_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    return storage_type
        
        # 2. 检查路径模式
        for storage_type, patterns in self.PATH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    return storage_type
        
        return None
    
    def detect_storage_from_response(self, resp: requests.Response) -> Tuple[Optional[str], str]:
        """从响应内容识别存储类型"""
        # 1. 检查响应头
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        headers_text = str(headers_lower)
        
        for storage_type, patterns in self.HEADER_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in headers_text:
                    return storage_type, f"Header: {pattern}"
        
        # 2. 检查响应内容 (XML)
        try:
            content = resp.text
            for pattern in self.XML_PATTERNS:
                if pattern in content:
                    # 进一步判断
                    if '<ListBucket' in content:
                        return 'unknown_bucket', f"XML: ListBucket"
                    elif 'AccessControlPolicy' in content:
                        return 'unknown_bucket', f"XML: ACL"
                    else:
                        return 'unknown', f"XML: {pattern[:30]}"
        except:
            pass
        
        # 3. 检查状态码和内容的特定组合
        if resp.status_code == 200:
            if '<!' in resp.text or '<?xml' in resp.text:
                return 'unknown_bucket', "XML content"
        
        if resp.status_code == 403:
            if 'AccessDenied' in resp.text:
                return 'private_bucket', "Private bucket (AccessDenied)"
        
        return None, "No storage signature found"
    
    def is_storage_endpoint(self, url: str, resp: requests.Response = None) -> Tuple[bool, Optional[str], str]:
        """
        综合判断是否为存储端点
        
        Returns:
            (is_storage, storage_type, reason)
        """
        # 1. URL 模式识别
        url_type = self.detect_storage_from_url(url)
        if url_type:
            return True, url_type, f"URL pattern: {url_type}"
        
        # 2. 如果没有 URL 模式，检查响应
        if resp:
            resp_type, resp_reason = self.detect_storage_from_response(resp)
            if resp_type:
                return True, resp_type, f"Response: {resp_reason}"
        
        # 3. 检查 URL 是否包含存储相关路径
        storage_paths = ['/minio/', '/oss/', '/cos/', '/s3/', '/bucket/', '/file/', '/upload/', '/storage/']
        for path in storage_paths:
            if path in url.lower():
                return True, 'unknown', f"Path pattern: {path}"
        
        return False, None, "Not a storage endpoint"
    
    def test_public_listing(self, bucket_url: str, storage_type: str = None) -> Tuple[bool, str]:
        """测试公开可列目录"""
        try:
            resp = self.session.get(bucket_url, timeout=10)
            
            # 检查是否返回 XML 文件列表
            if resp.status_code == 200:
                content = resp.text
                for pattern in self.XML_PATTERNS:
                    if pattern in content:
                        try:
                            root = ET.fromstring(content)
                            files = [elem.text for elem in root.iter() 
                                    if elem.tag.endswith('Key') and elem.text]
                            if files:
                                return True, f"公开可列目录 - 找到 {len(files)} 个文件"
                            return True, f"公开可列目录 - 返回 XML 格式列表 ({len(content)} bytes)"
                        except:
                            return True, f"公开可列目录 - 返回 XML 内容"
            
            if 'AccessDenied' in resp.text or resp.status_code == 403:
                return False, "正确拒绝 (403)"
            
            if resp.status_code == 404:
                return False, "资源不存在 (404)"
                
            return False, f"状态码: {resp.status_code}"
            
        except requests.exceptions.Timeout:
            return False, "请求超时"
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_anonymous_put(self, bucket_url: str, storage_type: str = None) -> Tuple[bool, str]:
        """测试匿名 PUT 上传"""
        import time
        test_content = f"STORAGE_TEST_{time.time()}"
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
    
    def test_anonymous_post(self, bucket_url: str, storage_type: str = None) -> Tuple[bool, str]:
        """测试匿名 POST 表单上传"""
        import time
        test_content = f"STORAGE_TEST_{time.time()}"
        
        try:
            files = {'file': ('test.txt', test_content, 'text/plain')}
            resp = self.session.post(bucket_url, files=files, timeout=10)
            
            if resp.status_code in [200, 201]:
                return True, f"可匿名 POST 上传 (状态码: {resp.status_code})"
            
            return False, f"POST 上传失败 (状态码: {resp.status_code})"
            
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_anonymous_delete(self, bucket_url: str, storage_type: str = None) -> Tuple[bool, str]:
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
    
    def test_sensitive_files(self, bucket_url: str, storage_type: str = None) -> Tuple[bool, List[str]]:
        """测试敏感文件泄露"""
        found = []
        
        for path in self.SENSITIVE_PATHS:
            try:
                resp = self.session.get(f"{bucket_url}/{path}", timeout=10)
                
                if resp.status_code == 200 and len(resp.content) > 0:
                    content = resp.text[:500].lower()
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
        
        return len(found) > 0, found[:10]
    
    def test_directory_traversal(self, bucket_url: str, storage_type: str = None) -> Tuple[bool, str]:
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
                    elif len(resp.text) > 50 and 'AccessDenied' not in resp.text:
                        return True, f"可能存在目录遍历 (路径: {path})"
                        
            except:
                pass
        
        return False, "未发现目录遍历"
    
    def test_cors_misconfiguration(self, bucket_url: str, storage_type: str = None) -> Tuple[bool, str]:
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
                return True, f"CORS 允许任意 Origin"
            
            if 'http://evil.com' in allow_origin:
                if allow_credentials.lower() == 'true':
                    return True, f"CORS 可利用 - Origin: evil.com, Credentials: true"
                return True, f"CORS 允许特定恶意 Origin"
            
            return False, "CORS 配置正常"
            
        except Exception as e:
            return False, f"CORS 检测失败: {e}"
    
    def test_log_exposure(self, bucket_url: str, storage_type: str = None) -> Tuple[bool, List[str]]:
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
    
    def test_version_exposure(self, bucket_url: str, storage_type: str = None) -> Tuple[bool, List[str]]:
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
                    found.append(path)
                    
            except:
                pass
        
        return len(found) > 0, found
    
    def test_acl_public(self, bucket_url: str, storage_type: str = None) -> Tuple[bool, str]:
        """测试 ACL 公共权限"""
        try:
            resp = self.session.get(f"{bucket_url}?acl", timeout=10)
            
            if resp.status_code == 200:
                content = resp.text
                if 'AllUsers' in content or 'AuthenticatedUsers' in content:
                    return True, "ACL 配置为公共访问"
                if '<Grant>' in content and 'FULL_CONTROL' in content:
                    return True, "ACL 存在完全控制权限"
            
            return False, "ACL 检查未发现明显问题"
            
        except Exception as e:
            return False, f"ACL 检测失败: {e}"
    
    def full_test(self, url: str, storage_type: str = None) -> Tuple[List[Dict], str]:
        """
        执行完整云存储安全测试
        
        Args:
            url: 存储桶 URL 或 API 端点
            storage_type: 已知的存储类型 (可选)
            
        Returns:
            (findings, detected_type)
        """
        print(f"[CloudStorage] 开始测试: {url}")
        
        # 1. 智能识别存储类型
        if not storage_type:
            # 先尝试获取响应来辅助判断
            try:
                resp = self.session.get(url, timeout=10)
                is_storage, storage_type, reason = self.is_storage_endpoint(url, resp)
                print(f"[CloudStorage] 识别结果: {storage_type} ({reason})")
            except:
                is_storage, storage_type, reason = self.is_storage_endpoint(url, None)
                print(f"[CloudStorage] 识别结果: {storage_type} ({reason})")
        else:
            is_storage = True
            reason = f"User specified: {storage_type}"
        
        if not is_storage:
            print(f"[CloudStorage] 不是存储端点，跳过: {reason}")
            return [], storage_type or 'unknown'
        
        results = []
        
        # 2. 公开可列目录
        print("[CloudStorage] [1/8] 测试公开可列目录...")
        is_public, msg = self.test_public_listing(url, storage_type)
        if is_public:
            results.append({
                'type': 'Public Listing',
                'severity': 'Critical',
                'evidence': msg,
                'url': url,
                'provider': storage_type
            })
        
        # 3. 匿名 PUT
        print("[CloudStorage] [2/8] 测试匿名 PUT 上传...")
        can_put, msg = self.test_anonymous_put(url, storage_type)
        if can_put:
            results.append({
                'type': 'Anonymous PUT Upload',
                'severity': 'Critical',
                'evidence': msg,
                'url': url,
                'provider': storage_type
            })
        
        # 4. 敏感文件
        print("[CloudStorage] [3/8] 测试敏感文件泄露...")
        has_sensitive, files = self.test_sensitive_files(url, storage_type)
        if has_sensitive:
            results.append({
                'type': 'Sensitive File Exposure',
                'severity': 'Critical',
                'evidence': ', '.join(files),
                'url': url,
                'provider': storage_type
            })
        
        # 5. 目录遍历
        print("[CloudStorage] [4/8] 测试目录遍历...")
        can_traverse, msg = self.test_directory_traversal(url, storage_type)
        if can_traverse:
            results.append({
                'type': 'Directory Traversal',
                'severity': 'High',
                'evidence': msg,
                'url': url,
                'provider': storage_type
            })
        
        # 6. CORS
        print("[CloudStorage] [5/8] 测试 CORS...")
        cors_vuln, msg = self.test_cors_misconfiguration(url, storage_type)
        if cors_vuln:
            results.append({
                'type': 'CORS Misconfiguration',
                'severity': 'High',
                'evidence': msg,
                'url': url,
                'provider': storage_type
            })
        
        # 7. 日志泄露
        print("[CloudStorage] [6/8] 测试日志泄露...")
        has_logs, log_files = self.test_log_exposure(url, storage_type)
        if has_logs:
            results.append({
                'type': 'Log Exposure',
                'severity': 'Medium',
                'evidence': ', '.join(log_files),
                'url': url,
                'provider': storage_type
            })
        
        # 8. 版本控制
        print("[CloudStorage] [7/8] 测试版本控制泄露...")
        has_versions, version_paths = self.test_version_exposure(url, storage_type)
        if has_versions:
            results.append({
                'type': 'Version Control Exposure',
                'severity': 'Medium',
                'evidence': ', '.join(version_paths),
                'url': url,
                'provider': storage_type
            })
        
        # 9. ACL
        print("[CloudStorage] [8/8] 测试 ACL 配置...")
        acl_issue, msg = self.test_acl_public(url, storage_type)
        if acl_issue:
            results.append({
                'type': 'ACL Public Access',
                'severity': 'High',
                'evidence': msg,
                'url': url,
                'provider': storage_type
            })
        
        print(f"[CloudStorage] 测试完成，发现 {len(results)} 个问题")
        return results, storage_type
    
    def discover_from_text(self, text: str) -> List[Dict]:
        """
        从文本 (JS/HTML/API 响应) 中发现存储桶 URL
        
        Returns:
            List of {url, type, reason}
        """
        found = []
        
        # 阿里云 OSS
        aliyun_patterns = [
            r'https?://[a-zA-Z0-9.-]+\.oss-[a-zA-Z0-9-]+\.aliyuncs\.com[^\s"\'<>]*',
            r'https?://[a-zA-Z0-9.-]+\.oss\.aliyuncs\.com[^\s"\'<>]*',
        ]
        
        # 腾讯云 COS
        tencent_patterns = [
            r'https?://[a-zA-Z0-9.-]+\.cos\.[a-zA-Z0-9.-]+\.myqcloud\.com[^\s"\'<>]*',
        ]
        
        # AWS S3
        aws_patterns = [
            r'https?://[a-zA-Z0-9.-]+\.s3\.[a-zA-Z0-9.-]+\.amazonaws\.com[^\s"\'<>]*',
        ]
        
        # MinIO (通常是路径模式)
        minio_patterns = [
            r'["\']/(?:minio|minio-api|bucket|file|upload)[^\s"\'<>]*',
            r'["\']/(?:api/s3)[^\s"\'<>]*',
        ]
        
        all_patterns = aliyun_patterns + tencent_patterns + aws_patterns + minio_patterns
        
        for pattern in all_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # 去重
                if not any(m['url'] == match for m in found):
                    if 'oss' in match.lower():
                        found.append({'url': match, 'type': 'aliyun', 'reason': 'URL pattern'})
                    elif 'cos' in match.lower():
                        found.append({'url': match, 'type': 'tencent', 'reason': 'URL pattern'})
                    elif 's3' in match.lower() or 'aws' in match.lower():
                        found.append({'url': match, 'type': 'aws', 'reason': 'URL pattern'})
                    else:
                        found.append({'url': match, 'type': 'minio', 'reason': 'Path pattern'})
        
        # 检查内网域名
        internal_patterns = [
            r'["\'](http[s]?://)[^"\']*?:900[01][^\s"\'<>]*',
            r'["\'](http[s]?://)[^"\']*?/minio[^\s"\'<>]*',
        ]
        
        for pattern in internal_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if not any(m['url'] == match for m in found):
                    found.append({'url': match, 'type': 'minio', 'reason': 'Internal/Path pattern'})
        
        return found


def test_current_domain_storage(target_url: str) -> List[Dict]:
    """
    测试当前域名的存储桶漏洞
    
    适用场景:
    - 域名是主站，但路由 /minio/, /file/ 等指向存储服务
    - 内网存储服务暴露在主站域名下
    """
    print(f"[CloudStorage] 测试当前域名存储服务: {target_url}")
    
    tester = CloudStorageTester()
    all_results = []
    
    # 常见的存储路径
    storage_paths = [
        '/minio/',
        '/minio-api/',
        '/file/',
        '/files/',
        '/upload/',
        '/uploads/',
        '/storage/',
        '/bucket/',
        '/oss/',
        '/cos/',
        '/s3/',
        '/api/file/',
        '/api/upload/',
        '/api/storage/',
        '/api/minio/',
    ]
    
    for path in storage_paths:
        url = target_url.rstrip('/') + path
        print(f"\n[CloudStorage] 测试路径: {path}")
        
        # 尝试检测存储类型
        try:
            resp = tester.session.head(url, timeout=10, allow_redirects=True)
        except:
            try:
                resp = tester.session.get(url, timeout=10)
            except Exception as e:
                print(f"[CloudStorage]   请求失败: {e}")
                continue
        
        # 智能判断是否为存储端点
        is_storage, storage_type, reason = tester.is_storage_endpoint(url, resp)
        
        if is_storage:
            print(f"[CloudStorage]   识别为存储: {storage_type} ({reason})")
            
            # 执行完整测试
            results, detected_type = tester.full_test(url, storage_type)
            all_results.extend(results)
            
            # 如果确认是存储，尝试更多路径
            if detected_type in ['minio', 'oss', 'cos', 's3']:
                # 尝试子路径
                for subpath in ['', '/public/', '/data/', '/backup/']:
                    suburl = url.rstrip('/') + subpath
                    try:
                        subresp = tester.session.head(suburl, timeout=5, allow_redirects=True)
                        subis, subtype, subreason = tester.is_storage_endpoint(suburl, subresp)
                        if subis and subtype == detected_type:
                            subresults, _ = tester.full_test(suburl, subtype)
                            all_results.extend(subresults)
                    except:
                        pass
        else:
            print(f"[CloudStorage]   不是存储端点 ({reason})")
    
    return all_results


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("用法:")
        print("  python cloud_storage_tester.py <bucket_url>")
        print("  python cloud_storage_tester.py --domain <main_domain>")
        print("\n示例:")
        print("  python cloud_storage_tester.py http://test.oss-cn-region.aliyuncs.com")
        print("  python cloud_storage_tester.py --domain http://58.215.18.57:91")
        sys.exit(1)
    
    if sys.argv[1] == '--domain':
        target = sys.argv[2] if len(sys.argv) > 2 else input("输入域名: ")
        results = test_current_domain_storage(target)
    else:
        bucket_url = sys.argv[1]
        tester = CloudStorageTester()
        results, detected = tester.full_test(bucket_url)
    
    print("\n" + "="*60)
    print("云存储安全测试结果")
    print("="*60)
    
    if not results:
        print("\n未发现云存储安全漏洞")
    else:
        for i, r in enumerate(results, 1):
            print(f"\n[{i}] {r['type']}")
            print(f"    Severity: {r['severity']}")
            print(f"    Evidence: {r['evidence']}")
            print(f"    URL: {r['url']}")
            print(f"    Provider: {r.get('provider', 'unknown')}")
