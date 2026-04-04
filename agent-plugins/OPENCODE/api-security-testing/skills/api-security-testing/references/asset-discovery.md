# 资产发现方法论

## 目录

1. [被动收集](#1-被动收集)
2. [主动探测](#2-主动探测)
3. [JavaScript 分析](#3-javascript-分析)
4. [Swagger/OpenAPI 发现](#4-swaggeropenapi-发现)
5. [云存储发现](#5-云存储发现)
6. [关联系统发现](#6-关联系统发现)
7. [指纹识别](#7-指纹识别)

---

## 1. 被动收集

### 1.1 DNS 记录收集

```python
# 被动 DNS 收集
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

def passive_dns_enum(domain):
    # 使用 SecurityTrails, VirusTotal, CRTSH 等被动源
    passive_sources = [
        f"https://securitytrails.com/api/v1/domain/{domain}/dns",
        f"https://crt.sh/?q=%.{domain}",
    ]
    
    for source in passive_sources:
        try:
            resp = requests.get(source, timeout=10)
            # 解析并收集子域名
        except:
            pass
```

### 1.2 SSL 证书收集

```python
# 从 SSL 证书中发现子域名
def cert_enumeration(domain):
    import socket
    import ssl
    
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            # 提取证书中的所有域名
            return cert.get('subjectAltName', [])
```

### 1.3 网页内容收集

```python
# 从 HTML 中提取链接和路径
def extract_from_html(html_content):
    patterns = {
        'links': r'href=["\']([^"\']+)["\']',
        'scripts': r'src=["\']([^"\']+\.js[^"\']*)["\']',
        'forms': r'action=["\']([^"\']+)["\']',
        'iframes': r'src=["\']([^"\']+)["\']',
        'comments': r'<!--([^-]|-[^-])*-->',
        'meta': r'<meta[^>]+content=["\']([^"\']+)["\']',
    }
    
    assets = {}
    for name, pattern in patterns.items():
        assets[name] = re.findall(pattern, html_content)
    
    return assets
```

---

## 2. 主动探测

### 2.1 子域名爆破

```python
# 子域名字典
SUBDOMAIN_WORDLIST = [
    # 通用
    "www", "mail", "ftp", "admin", "blog", "dev",
    "test", "staging", "demo", "api", "mobile",
    "vpn", "git", "gitlab", "jenkins", "ci",
    # 业务
    "oms", "cms", "erp", "crm", "scm", "wms",
    "ums", "rms", "pms", "bms", "fms",
    # 部门
    "hr", "finance", "it", "ops", "security",
    # 常用数字
    "test1", "test2", "dev1", "dev2",
    "staging1", "staging2",
]

def bruteforce_subdomains(domain, wordlist=SUBDOMAIN_WORDLIST):
    found = []
    for subdomain in wordlist:
        target = f"{subdomain}.{domain}"
        try:
            ip = socket.gethostbyname(target)
            found.append((target, ip))
            print(f"[+] Found: {target} -> {ip}")
        except socket.gaierror:
            pass
    return found
```

### 2.2 端口扫描

```python
# 常见 Web 端口
WEB_PORTS = [
    80, 443,     # HTTP/HTTPS
    8080, 8443,  # Alt HTTP
    3000, 3001,  # Dev servers
    5000, 5001,  # Python/Flask
    8000, 8001,  # Python
    8888,        # Jupyter
    9000,        # PHP-FPM
    9200,        # Elasticsearch
    27017,       # MongoDB
    6379,        # Redis
    3306,        # MySQL
    5432,        # PostgreSQL
    11211,       # Memcached
]

# 快速端口扫描
def quick_port_scan(host, ports=WEB_PORTS):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
            print(f"[+] Port {port} open")
        sock.close()
    return open_ports
```

### 2.3 路径爆破

```python
# 常见路径字典
PATH_WORDLIST = [
    # 管理后台
    "/admin", "/manage", "/management", "/administrator",
    "/login", "/signin", "/auth", "/oauth",
    "/dashboard", "/console", "/backend",
    # API
    "/api", "/api/v1", "/api/v2", "/rest",
    "/swagger", "/swagger-ui", "/api-docs",
    "/graphql", "/graphiql",
    # 文件
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.git/config", "/.env", "/config.php",
    "/backup", "/bak", "/old", "/debug",
    # 探测
    "/server-status", "/server-info",
    "/actuator", "/actuator/health",
]

def bruteforce_paths(base_url, wordlist=PATH_WORDLIST):
    found = []
    for path in wordlist:
        url = base_url.rstrip('/') + path
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                found.append((path, resp.status_code))
                print(f"[+] {path} ({resp.status_code})")
        except:
            pass
    return found
```

---

## 3. JavaScript 分析

### 3.1 JS 文件收集

```python
# 从 HTML 中提取所有 JS 文件
def collect_js_files(html_content):
    js_files = []
    
    # script src
    patterns = [
        r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
        r'"(/_next/static/[^"]+\.js)"',
        r'"(/static/js/[^"]+\.js)"',
        r'"(https://[^"]+\.js)"',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, html_content)
        js_files.extend(matches)
    
    # 去重
    return list(set(js_files))
```

### 3.2 API 端点提取

```python
# 从 JS 中提取 API 端点
API_PATTERNS = [
    # axios/fetch
    r'["\'](/(?:api|auth|admin|user|login|logout)[^"\']*)["\']',
    r'\.(?:get|post|put|delete|patch)\\(["\']([^"\']+)["\']\\)',
    # URL patterns
    r'["\']https?://[^"\']+(?:api|auth|admin)[^"\']*["\']',
    # baseURL
    r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
    # webpack chunk
    r'"(?:chunk-|js/)([a-f0-9]+)"',
]

def extract_api_from_js(js_content):
    endpoints = set()
    
    for pattern in API_PATTERNS:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                endpoints.update(match)
            else:
                endpoints.add(match)
    
    return list(endpoints)
```

### 3.3 敏感信息提取

```python
# 敏感信息正则
SENSITIVE_PATTERNS = {
    'api_key': [
        r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
        r'["\'](?:sk|pk|api)[_-][a-zA-Z0-9]{20,}["\']',
    ],
    'aws_key': [
        r'AKIA[0-9A-Z]{16}',
        r'(?:aws[_-]?)?(?:access[_-]?key[_-]?id|secret[_-]?key)',
    ],
    'jwt': [
        r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
    ],
    'private_key': [
        r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    ],
    'ip_address': [
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    ],
    'internal_host': [
        r'(?:https?://)?(?:[a-z0-9-]+\.)+(?:local|internal|lan|intranet)(?::\d+)?',
        r'http://192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?',
        r'http://10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?',
    ],
}

def extract_sensitive_info(js_content):
    findings = {}
    for info_type, patterns in SENSITIVE_PATTERNS.items():
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                findings[info_type] = list(set(matches))
    return findings
```

---

## 4. Swagger/OpenAPI 发现

### 4.1 常见 Swagger 路径

```python
# Swagger 路径字典
SWAGGER_PATHS = [
    # Swagger UI
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger-ui/swagger-ui-bundle.js",
    "/swagger-ui-standalone-preset.js",
    # OpenAPI
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/api-docs.json",
    "/openapi.json",
    "/openapi.yaml",
    # Swagger 2.0
    "/swagger.json",
    "/swagger.yaml",
    # 其他
    "/doc.html",
    "/swagger/index.html",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api-docs/swagger.json",
]

def probe_swagger(base_url):
    for path in SWAGGER_PATHS:
        url = base_url + path
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                if 'swagger' in resp.text.lower() or 'openapi' in resp.text.lower():
                    print(f"[+] Found: {url}")
                    return url
        except:
            pass
    return None
```

### 4.2 解析 OpenAPI Schema

```python
# 解析 OpenAPI JSON
def parse_openapi_schema(schema_url):
    resp = requests.get(schema_url)
    schema = resp.json()
    
    api_info = {
        'title': schema.get('info', {}).get('title'),
        'version': schema.get('info', {}).get('version'),
        'basePath': schema.get('basePath'),
        'servers': [s.get('url') for s in schema.get('servers', [])],
        'endpoints': []
    }
    
    # 提取所有端点
    for path, methods in schema.get('paths', {}).items():
        for method, details in methods.items():
            if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                api_info['endpoints'].append({
                    'path': path,
                    'method': method.upper(),
                    'summary': details.get('summary'),
                    'parameters': details.get('parameters', []),
                    'requestBody': details.get('requestBody'),
                    'responses': details.get('responses'),
                })
    
    return api_info
```

---

## 5. 云存储发现

### 5.1 云存储 URL 模式

```python
# 云存储 URL 正则
CLOUD_STORAGE_PATTERNS = {
    'aliyun_oss': [
        r'[a-z0-9-]+\.oss-(?:cn-[a-z0-9-]+)\.aliyuncs\.com',
        r'https?://(?:[a-z0-9-]+\.)?oss-[a-z0-9-]+\.aliyuncs\.com',
    ],
    'aws_s3': [
        r'[a-z0-9-]+\.s3(?:(?:\.|\-)[a-z0-9-]+)?\.amazonaws\.com',
        r's3(?:(?:\.|\-)[a-z0-9-]+)?\.amazonaws\.com/[a-z0-9-]+',
    ],
    'tencent_cos': [
        r'[a-z0-9-]+\.cos\.[a-z0-9-]+\.myqcloud\.com',
        r'https?://(?:[a-z0-9-]+\.)?cos\.myqcloud\.com',
    ],
    'huawei_obs': [
        r'[a-z0-9-]+\.obs\.[a-z0-9-]+\.hwclouds\.com',
        r'https?://(?:[a-z0-9-]+\.)?obs\.hwclouds\.com',
    ],
    'minio': [
        r'[a-z0-9-]+\.minio\.[a-z0-9.-]+',
        r'http://minio(?:[a-z0-9.-]+)?:\d+',
    ],
}

def detect_cloud_storage(content):
    findings = []
    for provider, patterns in CLOUD_STORAGE_PATTERNS.items():
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'provider': provider,
                    'url': match if '://' in match else f'http://{match}'
                })
    return findings
```

### 5.2 云存储探测

```python
# 云存储探测函数
def probe_cloud_storage(bucket_url):
    tests = [
        # 列出目录
        ("GET", "", None, [200], "list_bucket"),
        # 上传测试
        ("PUT", "test.txt", b"test", [200, 201], "put_object"),
        # 获取上传的文件
        ("GET", "test.txt", None, [200], "get_object"),
    ]
    
    results = []
    for method, path, data, expected_codes, test_name in tests:
        url = bucket_url.rstrip('/') + '/' + path
        try:
            if method == "GET":
                resp = requests.get(url, timeout=10)
            elif method == "PUT":
                resp = requests.put(url, data=data, timeout=10)
            
            if resp.status_code in expected_codes:
                results.append({
                    'test': test_name,
                    'status': 'success',
                    'details': resp.status_code
                })
        except Exception as e:
            results.append({
                'test': test_name,
                'status': 'failed',
                'error': str(e)
            })
    
    return results
```

---

## 6. 关联系统发现

### 6.1 内网地址发现

```python
# 从响应中提取内网地址
INTERNAL_IP_PATTERNS = [
    # 私有IP
    r'http://192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s]*)?',
    r'http://10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s]*)?',
    r'http://172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s]*)?',
    # localhost
    r'http://localhost(?::\d+)?(?:/[^\s]*)?',
    r'http://127\.0\.0\.1(?::\d+)?(?:/[^\s]*)?',
    # Docker/K8s
    r'http://172\.(?:1[7-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?::\d+)?',
]

def extract_internal_ips(content):
    findings = []
    for pattern in INTERNAL_IP_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        findings.extend(matches)
    return list(set(findings))
```

### 6.2 系统关联发现

```python
# 从响应头提取 Server 信息
def extract_server_info(response_headers):
    info = {
        'server': response_headers.get('Server', ''),
        'xPoweredBy': response_headers.get('X-Powered-By', ''),
        'via': response_headers.get('Via', ''),
    }
    
    # 提取版本信息
    for header_value in info.values():
        version_match = re.findall(r'(\d+\.\d+\.\d+)', header_value)
        if version_match:
            info['versions'] = version_match
    
    return info

# 常见系统 URL 模式
SYSTEM_PATTERNS = {
    'admin': '/admin', '/administrator', '/manage',
    'monitoring': '/monitor', '/health', '/status',
    'database': '/phpmyadmin', '/adminer', '/pgadmin',
    'devops': '/jenkins', '/gitlab', '/jira', '/confluence',
    'storage': '/oss', '/files', '/upload',
}
```

---

## 7. 指纹识别

### 7.1 技术栈识别

```python
# 技术栈指纹
TECH_FINGERPRINTS = {
    'frontend': {
        'vue': ['vue.js', 'vue.min.js', '__vue__', 'Vue'],
        'react': ['react.js', 'react.min.js', '_react', 'React'],
        'angular': ['angular.js', 'angular.min.js', 'ng-app', 'Angular'],
        'jquery': ['jquery.js', 'jquery.min.js', 'jQuery'],
    },
    'backend': {
        'express': ['Express', 'x-powered-by', 'express-session'],
        'django': ['csrftoken', 'csrfmiddlewaretoken', 'django'],
        'flask': ['flask', 'session', ' werkzeug'],
        'spring': ['JSESSIONID', 'spring', 'GRAILS_'],
        'rails': ['_session_id', 'Ruby on Rails'],
        'laravel': ['laravel_session', 'XSRF-TOKEN'],
    },
    'server': {
        'nginx': ['nginx', 'Server: nginx'],
        'apache': ['apache', 'Server: apache'],
        'iis': ['IIS', 'X-AspNet-Version'],
        'tomcat': ['Apache-Coyote', 'tomcat'],
    },
}

def identify_tech_stack(html_content, headers):
    identified = {'frontend': [], 'backend': [], 'server': []}
    
    content = html_content + str(headers)
    
    for category, fingerprints in TECH_FINGERPRINTS.items():
        for tech, keywords in fingerprints.items():
            for keyword in keywords:
                if keyword.lower() in content.lower():
                    identified[category].append(tech)
                    break
    
    return identified
```

### 7.2 CMS 识别

```python
# CMS 指纹
CMS_PATTERNS = {
    'wordpress': [
        '/wp-content/',
        '/wp-includes/',
        'wp-json',
        'WordPress',
    ],
    'drupal': [
        '/sites/default/',
        'drupal.js',
        'Drupal.settings',
    ],
    'joomla': [
        '/media/jui/',
        'Joomla!',
        'option=com_',
    ],
    'dedecms': [
        '/templets/default/',
        'DedeCms',
        'dede_',
    ],
    'discuz': [
        '/static/image/common/',
        'Discuz!',
        'forum.php',
    ],
}
```

---

## 附录：资产发现检查清单

```
□ 被动收集
  □ SSL 证书分析
  □ DNS 记录收集
  □ 网页内容提取

□ 主动探测
  □ 子域名爆破
  □ 端口扫描
  □ 路径爆破

□ JS 分析
  □ JS 文件收集
  □ API 端点提取
  □ 敏感信息发现

□ API 文档
  □ Swagger 发现
  □ OpenAPI 解析
  □ API 端点整理

□ 云存储
  □ 云存储 URL 发现
  □ Bucket 权限测试

□ 关联系统
  □ 内网地址发现
  □ 系统关联分析

□ 指纹识别
  □ 技术栈识别
  □ CMS 识别
  □ 版本信息收集
```
