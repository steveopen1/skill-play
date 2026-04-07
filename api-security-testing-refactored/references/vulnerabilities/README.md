# 漏洞测试方法索引

本目录沉淀了API安全测试的知识库，包括：
- 攻击模式与Payload
- 测试检查清单
- 漏洞验证标准
- 利用链构造方法

> **核心理念**：Skill是引导者而非自动化工具。本目录提供的是知识框架和思考方向，帮助人类测试者做出判断，而不是替代人类执行测试。

## 分类目录

### [01-sqli-tests.md](./01-sqli-tests.md)
**SQL 注入测试**
- 注释绕过、OR绕过、UNION注入
- 布尔注入、时间盲注、报错注入
- **【新增】WAF绕过方法**（大小写、内联注释、双写、空格替代、编码）
- **【新增】详细利用链**（MySQL、MSSQL、PostgreSQL、Oracle、Redis、MongoDB）
- **【新增】SQL注入新思路**（Header注入、路径注入、隐藏参数）

### [02-user-enum-tests.md](./02-user-enum-tests.md)
**用户枚举测试**
- 用户名、手机号、邮箱枚举
- 登录接口响应差异
- 注册接口探测
- 常见账号字典
- **【新增】curl基准对比验证**
- **【新增】Python自动化脚本**

### [03-jwt-tests.md](./03-jwt-tests.md)
**JWT 认证测试**
- 空Token、alg:none、算法篡改
- 密钥混淆、kid注入
- 重放攻击测试
- **【新增】误报判断标准**
- **【新增】curl对比验证流程**

### [04-idor-tests.md](./04-idor-tests.md)
**IDOR 越权测试**
- 水平越权、垂直越权
- 批量遍历测试
- POST参数篡改
- **【新增】curl基准对比**
- **【新增】多维度判断矩阵**

### [05-sensitive-data-tests.md](./05-sensitive-data-tests.md)
**敏感信息泄露测试**
- 认证信息、金融信息、个人信息
- 登录/用户信息响应检查
- 错误信息指纹识别
- 脱敏检测
- **【新增】curl对比验证**
- **【新增】脱敏检测脚本**

### [06-biz-logic-tests.md](./06-biz-logic-tests.md)
**业务逻辑漏洞测试**
- 支付篡改（金额、数量、状态）
- 条件竞争（优惠券、库存）
- 业务流程绕过
- **【新增】curl对比验证**
- **【新增】Python并发测试脚本**

### [07-security-config-tests.md](./07-security-config-tests.md)
**安全配置漏洞测试**
- CORS配置（ACAO + ACAC）
- 安全响应头缺失
- 路径遍历、SSRF
- **【新增】CORS风险矩阵**
- **【新增】curl验证流程**

### [08-brute-force-tests.md](./08-brute-force-tests.md)
**暴力破解测试**
- 登录暴力破解
- 验证码暴力破解
- 防护检查与绕过
- **【新增】误报判断标准**
- **【新增】Python自动化脚本**

### [09-vulnerability-chains.md](./09-vulnerability-chains.md)
**漏洞关联联想**
- 漏洞关联矩阵
- 攻击链模板
- 漏洞优先级排序
- 组合利用示例
- **【新增】curl攻击链验证脚本**

### [10-auth-tests.md](./10-auth-tests.md) ⭐ NEW
**认证漏洞完整测试**
- SQL注入绕过认证
- Session Fixation/Hijacking
- 密码重置Token预测/泄露/复用
- **OAuth/OIDC漏洞**（redirect_uri绕过、state缺失、scope扩大）
- **SAML漏洞**（签名绕过、重放）
- **2FA/OTP绕过**（暴力破解、码复用、跳过）
- 完整curl和Python测试脚本

### [11-graphql-tests.md](./11-graphql-tests.md) ⭐ NEW
**GraphQL安全测试**
- 内省查询滥用
- 批量查询绕过速率限制
- 嵌套查询DoS
- 字段级权限绕过
- GraphQL SQL注入
- SSRF through GraphQL
- 完整curl测试模板

### [12-ssrf-tests.md](./12-ssrf-tests.md) ⭐ NEW
**SSRF安全测试**
- SSRF测试点识别
- 本地地址/云元数据/协议测试
- 云服务利用（AWS/GCP/Azure）
- **利用链**（Redis写入WebShell、MySQL连接）
- IP/URL绕过技巧
- 完整curl和Python测试脚本

## 使用方式

```markdown
# Agent 按需读取示例

## 场景1：发现可疑的登录接口
→ 阅读 02-user-enum-tests.md（用户枚举）
→ 阅读 08-brute-force-tests.md（暴力破解）
→ 阅读 10-auth-tests.md（完整认证漏洞）

## 场景2：发现SQL注入
→ 阅读 01-sqli-tests.md（SQL注入 + WAF绕过 + 利用链）
→ 阅读 09-vulnerability-chains.md（关联联想）

## 场景3：发现可疑的URL参数
→ 阅读 12-ssrf-tests.md（SSRF测试）
→ 阅读 11-graphql-tests.md（GraphQL安全）

## 场景4：需要进行完整渗透测试
→ 按顺序阅读所有文件
→ 使用 09-vulnerability-chains.md 整理攻击链
```

## 快速查询

| 漏洞类型 | 文件 | 特色内容 |
|----------|------|----------|
| SQL注入 | 01-sqli-tests.md | WAF绕过、利用链、新思路 |
| 用户枚举 | 02-user-enum-tests.md | curl对比验证 |
| JWT认证 | 03-jwt-tests.md | 误报判断 |
| IDOR越权 | 04-idor-tests.md | curl基准对比 |
| 敏感信息 | 05-sensitive-data-tests.md | 脱敏检测 |
| 业务逻辑 | 06-biz-logic-tests.md | 条件竞争测试 |
| 安全配置 | 07-security-config-tests.md | CORS风险矩阵 |
| 暴力破解 | 08-brute-force-tests.md | Python自动化 |
| 漏洞关联 | 09-vulnerability-chains.md | curl攻击链脚本 |
| 认证漏洞 | 10-auth-tests.md | OAuth/SAML/2FA完整 |
| GraphQL | 11-graphql-tests.md | 内省滥用/DoS |
| SSRF | 12-ssrf-tests.md | 云元数据/利用链 |
