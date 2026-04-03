# 用户枚举测试

## 1. 概述

用户枚举（User Enumeration）是指通过某些接口可以判断用户名、手机号、邮箱等是否存在于系统中。

**危险等级**: 中

## 2. 测试点识别

### 2.1 常见枚举接口

| 接口模式 | 示例 |
|----------|------|
| 用户查重 | `/user/checkOnlyUser?username=X` |
| 用户存在 | `/user/exist?phone=X` |
| 用户验证 | `/user/validate?email=X` |
| 注册接口 | `/user/register` |
| 登录接口 | `/login` (响应差异) |
| 密码重置 | `/user/resetPassword` |

### 2.2 响应差异点

| 特征 | 说明 |
|------|------|
| 不同错误消息 | "用户不存在" vs "密码错误" |
| 响应码差异 | code=0 vs code=1 |
| 响应时间差异 | 存在用户 vs 不存在 |

## 3. 测试方法

### 3.1 用户名枚举

```bash
# 用户存在
curl "http://api/sys/user/checkOnlyUser?username=admin"
# 响应: {"success":false,"message":"用户账号已存在","code":0,"result":true}

# 用户不存在
curl "http://api/sys/user/checkOnlyUser?username=notexist"
# 响应: {"success":false,"message":"","code":0,"result":false}
```

### 3.2 手机号枚举

```bash
curl "http://api/user/check?phone=13800138000"
curl "http://api/user/existByPhone?phone=13800138000"
curl "http://api/sms/send?phone=13800138000"
```

### 3.3 邮箱枚举

```bash
curl "http://api/user/check?email=test@mail.com"
curl "http://api/user/validateEmail?email=test@mail.com"
```

### 3.4 登录接口响应差异

```bash
# 用户不存在
POST /api/login
{"username": "notexist", "password": "any"}
# 响应: {"message":"用户不存在"}

# 密码错误
POST /api/login
{"username": "admin", "password": "wrong"}
# 响应: {"message":"密码错误"}

# 用户存在但响应相同
POST /api/login
{"username": "notexist", "password": "wrong"}
# 响应: {"message":"用户名或密码错误"}  ← 统一消息（安全）
```

### 3.5 注册接口探测

```bash
POST /api/user/register
{"username": "admin", "password": "test"}
# 响应: {"message":"该用户已注册"}

POST /api/user/register
{"username": "newuser", "password": "test"}
# 响应: {"message":"注册成功"}
```

## 4. 枚举用户名字典

### 4.1 常见管理员账号

```
admin, administrator, root, user, manager
sysadmin, system, security, backup
admin1, admin123, admin888
root1, root123
administrator, adminitrator (拼写错误)
```

### 4.2 常见测试账号

```
test, test1, test123, tester
demo, demo1
guest, visitor
default
```

### 4.3 业务相关账号

```
owner, operator, developer
support, helpdesk
noreply, no-reply
```

## 5. 防护绕过

### 5.1 大小写混淆

```bash
username=Admin
username=ADMIN
username=AdMiN
```

### 5.2 特殊字符

```bash
username=admin
username=admin\
username=admin"
username=admin<>
```

### 5.3 时间差异规避

```bash
# 多次请求间增加延迟
sleep 1
curl "http://api/user/check?username=admin"
```

## 6. 关联漏洞

| 后续漏洞 | 利用路径 |
|----------|----------|
| 暴力破解 | 确认用户名 → 定向爆破密码 |
| 密码重置 | 利用已确认的用户 → 重置密码 |
| 社会工程学 | 利用确认的手机号/邮箱 → 钓鱼攻击 |

## 7. 测试检查清单

```
□ 测试用户查重接口（/user/checkOnlyUser）
□ 测试手机号查重接口
□ 测试邮箱查重接口
□ 测试登录接口响应差异
□ 测试注册接口探测
□ 枚举常见管理员账号
□ 枚举常见测试账号
□ 测试大小写绕过
□ 测试特殊字符绕过
□ 判断响应差异是否可利用
□ 评估漏洞风险和影响
```

## 8. 误报判断标准

### 8.1 核心判断原则

```
【重要】响应差异 ≠ 用户枚举漏洞！

判断逻辑：
1. 先获取正常响应基准
2. 对比有效用户和无效用户的响应
3. 差异必须是"明确的用户存在/不存在指示"

【真实漏洞特征】
- 明确区分"用户不存在"和"密码错误"
- 响应中直接包含"用户已存在"等字样
- 响应时间有明显差异（数据库查询 vs 直接返回）

【误报特征】
- 有效/无效用户返回相同错误消息
- 响应差异只是"参数格式校验"失败
- WAF拦截导致的响应差异
```

### 8.2 curl + 对比验证流程

```bash
# 1. 【必须先执行】获取正常响应基准
curl -s -X POST http://api/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"wrong"}' > enum_baseline.json

# 2. 测试可能存在的用户
curl -s -X POST http://api/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"wrong"}' > enum_test1.json

# 3. 测试不存在的用户
curl -s -X POST http://api/login \
     -H "Content-Type: application/json" \
     -d '{"username":"nonexist_abc123","password":"wrong"}' > enum_test2.json

# 4. 对比两次响应
diff enum_baseline.json enum_test1.json
# 应该完全相同（如果都返回"用户名或密码错误"）

diff enum_baseline.json enum_test2.json
# 判断：
# - 完全相同 → 不是用户枚举漏洞（安全）
# - 有明显差异 → 可能是用户枚举漏洞
```

### 8.3 多维度判断矩阵

| 场景 | 响应A | 响应B | 差异 | 判断 |
|------|-------|-------|------|------|
| 正常 | {"msg":"用户名或密码错误"} | {"msg":"用户名或密码错误"} | 无 | ✅ 安全 |
| 正常 | {"msg":"用户名或密码错误"} | {"msg":"用户不存在"} | 有 | ⚠️ 可能漏洞 |
| 误报 | {"msg":"参数格式错误"} | {"msg":"用户名或密码错误"} | 有 | ❌ 误报（格式校验） |
| 误报 | {"msg":"请输入密码"} | {"msg":"密码错误"} | 有 | ❌ 误报（字段缺失） |

### 8.4 Python脚本（复杂场景）

```python
import requests
import json

class UserEnumTester:
    def __init__(self, target):
        self.target = target
        self.baseline = None
        
    def get_baseline(self):
        """获取正常响应基准（无效用户）"""
        resp = requests.post(
            f"{self.target}/login",
            json={"username": "nonexist_abc123", "password": "wrong"},
            headers={"Content-Type": "application/json"}
        )
        self.baseline = resp.json()
        return self.baseline
    
    def is_user_exists(self, username):
        """
        测试用户是否存在
        
        Returns:
            (exists, reason, response)
            - exists: True/False/Unknown
            - reason: 判断原因
            - response: 完整响应
        """
        resp = requests.post(
            f"{self.target}/login",
            json={"username": username, "password": "wrong"},
            headers={"Content-Type": "application/json"}
        )
        
        if resp.status_code != 200:
            return False, "HTTP错误", resp
        
        try:
            data = resp.json()
        except:
            return False, "非JSON响应", resp
        
        # 检查响应是否与基准完全相同
        if self.baseline and data == self.baseline:
            return False, "响应与基准相同（可能是安全）", data
        
        # 检查是否有明确的用户存在指示
        msg = data.get('msg', '').lower()
        code = str(data.get('code', ''))
        
        # 用户不存在的指示
        not_exist_keywords = ['不存在', 'not exist', 'not found', '用户不存在']
        # 用户存在的指示
        exist_keywords = ['已存在', 'exist', '用户已注册', '密码错误', '密码不匹配']
        
        for kw in not_exist_keywords:
            if kw in msg:
                return False, f"响应包含'{kw}'，用户可能不存在", data
        
        for kw in exist_keywords:
            if kw in msg:
                return True, f"响应包含'{kw}'，用户可能存在", data
        
        # 检查响应码差异
        if self.baseline:
            if data.get('code') != self.baseline.get('code'):
                return None, f"响应码不同(A:{self.baseline.get('code')} B:{data.get('code')})", data
        
        return None, "响应有差异但无法判断", data
    
    def run_tests(self, usernames):
        """批量测试用户枚举"""
        print(f"\n=== 用户枚举测试 ===\n")
        
        # 获取基准
        self.get_baseline()
        print(f"基准响应: {self.baseline}\n")
        
        results = {'exists': [], 'not_exists': [], 'unknown': []}
        
        for username in usernames:
            exists, reason, resp = self.is_user_exists(username)
            
            if exists is True:
                results['exists'].append({
                    'username': username,
                    'reason': reason,
                    'response': resp
                })
                print(f"[存在] {username}: {reason}")
            elif exists is False:
                results['not_exists'].append({
                    'username': username,
                    'reason': reason,
                    'response': resp
                })
                print(f"[不存在] {username}: {reason}")
            else:
                results['unknown'].append({
                    'username': username,
                    'reason': reason,
                    'response': resp
                })
                print(f"[未知] {username}: {reason}")
        
        return results

# 使用示例
if __name__ == "__main__":
    tester = UserEnumTester("http://api")
    
    test_users = [
        'admin', 'administrator', 'root', 'user', 'test',
        'demo', 'guest', 'nonexist_abc123', 'superadmin'
    ]
    
    results = tester.run_tests(test_users)
    
    print(f"\n=== 测试结果汇总 ===")
    print(f"存在: {len(results['exists'])}个")
    print(f"不存在: {len(results['not_exists'])}个")
    print(f"未知: {len(results['unknown'])}个")
    
    # 如果存在unknown，需要进一步分析
    if results['unknown']:
        print(f"\n[注意] 存在{len(results['unknown'])}个无法确认的用户")
        print("建议：人工分析这些用户的响应，确定是否为漏洞")
```

## 9. 实战判断案例

### 案例1：安全的登录接口

```
【场景】：所有用户名返回相同错误消息

curl测试：
  curl -X POST /api/login -d '{"username":"admin","password":"wrong"}'
  → {"code":"90000","msg":"用户名或密码错误。"}

  curl -X POST /api/login -d '{"username":"nonexist","password":"wrong"}'
  → {"code":"90000","msg":"用户名或密码错误。"}

判断：
- 响应完全相同
- 结论：【安全】不是用户枚举漏洞
```

### 案例2：真实用户枚举

```
【场景】：有效/无效用户返回不同消息

curl测试：
  curl -X POST /api/login -d '{"username":"admin","password":"wrong"}'
  → {"code":"90001","msg":"密码错误，用户账号存在。"}

  curl -X POST /api/login -d '{"username":"nonexist","password":"wrong"}'
  → {"code":"90002","msg":"用户不存在。"}

判断：
- 有效用户："密码错误，用户账号存在"
- 无效用户："用户不存在"
- 结论：【确认漏洞】可枚举有效用户
```

### 案例3：参数格式校验误报

```
【场景】：响应差异但不是用户枚举

curl测试：
  curl -X POST /api/login -d '{"username":"","password":""}'
  → {"code":"90003","msg":"参数不能为空。"}

  curl -X POST /api/login -d '{"username":"admin","password":"wrong"}'
  → {"code":"90000","msg":"用户名或密码错误。"}

判断：
- 差异是"参数为空" vs "用户名或密码错误"
- 这是参数格式校验，不是用户枚举
- 结论：【误报】需要填充有效用户名再测试
```

## 10. 风险评估

| 风险级别 | 条件 |
|----------|------|
| 高 | 可快速枚举大量用户/邮箱，无限制 |
| 中 | 有一定限制但可枚举个 |
| 低 | 有严格限制但仍可枚举 |
