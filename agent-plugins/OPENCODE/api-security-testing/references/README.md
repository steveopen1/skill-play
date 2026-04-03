# API Security Testing 参考资源

## 核心文件

| 文件 | 内容 |
|------|------|
| `pua-agent.md` | PUA自动测试Agent，强制深入不放弃 |
| `fuzzing-patterns.md` | API Fuzzing字典 |
| `report-template.md` | 安全测试报告模板 |

## vulnerabilities/ 漏洞测试方法

| 文件 | 内容 |
|------|------|
| `vulnerabilities/01-sqli-tests.md` | SQL注入测试 + WAF绕过 |
| `vulnerabilities/02-user-enum-tests.md` | 用户枚举测试 |
| `vulnerabilities/03-jwt-tests.md` | JWT认证测试 |
| `vulnerabilities/04-idor-tests.md` | IDOR越权测试 |
| `vulnerabilities/05-sensitive-data-tests.md` | 敏感信息泄露 |
| `vulnerabilities/06-biz-logic-tests.md` | 业务逻辑漏洞 |
| `vulnerabilities/07-security-config-tests.md` | 安全配置漏洞 |
| `vulnerabilities/08-brute-force-tests.md` | 暴力破解测试 |
| `vulnerabilities/09-vulnerability-chains.md` | 漏洞关联联想 |
| `vulnerabilities/10-auth-tests.md` | OAuth/SAML/2FA测试 |
| `vulnerabilities/11-graphql-tests.md` | GraphQL安全测试 |
| `vulnerabilities/12-ssrf-tests.md` | SSRF测试 |

## PUA Agent 使用

### 核心思想

```
【PUA自动模式】
- 发现线索 → 自动深入
- 不等待用户指令
- 压力升级直到完成
```

### 压力升级机制

| 失败次数 | 级别 | 行动 |
|---------|------|------|
| 1次 | L1 | 换方法继续 |
| 2次 | L2 | 强制检查清单 |
| 3次 | L3 | 报告进度并继续 |
| 4次+ | L4 | 尝试其他方向 |

### 不放弃原则

```
遇到以下情况必须继续：
□ 端点404 → 尝试POST方法
□ 被WAF拦截 → 换payload
□ 返回HTML → 继续API测试
□ 找不到配置 → 搜索其他JS
□ 一个端点失败 → 测试同类端点
□ 说"无法测试" → 必须穷举所有方法
```

### 进度追踪表

```
阶段1: [████████░░] 80%
阶段2: [████░░░░░░░] 40%
阶段3: [░░░░░░░░░░░] 0%
阶段4: [░░░░░░░░░░░] 0%

发现:
├─ CORS漏洞: 18个端点
├─ SQL注入: 待测试
└─ 新线索: /ipark-wxlite/*
```
