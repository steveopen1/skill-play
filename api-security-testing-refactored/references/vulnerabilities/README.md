# 漏洞测试方法索引

本文档按类型分类，便于按需查阅。

## 分类目录

### [01-sqli-tests.md](./01-sqli-tests.md)
**SQL 注入测试**
- 注释绕过、OR绕过、UNION注入
- 布尔注入、时间盲注、报错注入
- 数据库指纹识别

### [02-user-enum-tests.md](./02-user-enum-tests.md)
**用户枚举测试**
- 用户名、手机号、邮箱枚举
- 登录接口响应差异
- 注册接口探测
- 常见账号字典

### [03-jwt-tests.md](./03-jwt-tests.md)
**JWT 认证测试**
- 空Token、alg=none、算法篡改
- 密钥混淆、kid注入
- 重放攻击测试

### [04-idor-tests.md](./04-idor-tests.md)
**IDOR 越权测试**
- 水平越权、垂直越权
- 批量遍历测试
- POST参数篡改

### [05-sensitive-data-tests.md](./05-sensitive-data-tests.md)
**敏感信息泄露测试**
- 认证信息、金融信息、个人信息
- 登录/用户信息响应检查
- 错误信息指纹识别
- 脱敏检测

### [06-biz-logic-tests.md](./06-biz-logic-tests.md)
**业务逻辑漏洞测试**
- 支付篡改（金额、数量、状态）
- 条件竞争（优惠券、库存）
- 业务流程绕过

### [07-security-config-tests.md](./07-security-config-tests.md)
**安全配置漏洞测试**
- CORS配置（ACAO + ACAC）
- 安全响应头缺失
- 路径遍历、SSRF

### [08-brute-force-tests.md](./08-brute-force-tests.md)
**暴力破解测试**
- 登录暴力破解
- 验证码暴力破解
- 防护检查与绕过

### [09-vulnerability-chains.md](./09-vulnerability-chains.md)
**漏洞关联联想**
- 漏洞关联矩阵
- 攻击链模板
- 漏洞优先级排序
- 组合利用示例

## 使用方式

```markdown
# Agent 按需读取示例

## 场景1：发现可疑的登录接口
→ 阅读 02-user-enum-tests.md（用户枚举）
→ 阅读 08-brute-force-tests.md（暴力破解）

## 场景2：发现SQL注入
→ 阅读 01-sqli-tests.md（SQL注入）
→ 阅读 09-vulnerability-chains.md（关联联想）

## 场景3：需要进行完整渗透测试
→ 按顺序阅读所有文件
→ 使用 09-vulnerability-chains.md 整理攻击链
```

## 快速查询

| 漏洞类型 | 文件 | 行数 |
|----------|------|------|
| SQL注入 | 01-sqli-tests.md | ~150 |
| 用户枚举 | 02-user-enum-tests.md | ~130 |
| JWT认证 | 03-jwt-tests.md | ~140 |
| IDOR越权 | 04-idor-tests.md | ~130 |
| 敏感信息 | 05-sensitive-data-tests.md | ~150 |
| 业务逻辑 | 06-biz-logic-tests.md | ~130 |
| 安全配置 | 07-security-config-tests.md | ~150 |
| 暴力破解 | 08-brute-force-tests.md | ~130 |
| 漏洞关联 | 09-vulnerability-chains.md | ~180 |
