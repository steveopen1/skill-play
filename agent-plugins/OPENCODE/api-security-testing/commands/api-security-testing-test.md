---
description: API 安全测试 - 快速测试特定端点
---

<command-instruction>
对特定 API 端点进行快速安全测试。

## 使用方法

```
/api-security-testing-test <端点URL> [测试类型]
```

## 示例

```
/api-security-testing-test https://example.com/api/login sqli
/api-security-testing-test https://example.com/api/user idor
```

## 测试类型

| 类型 | 说明 |
|------|------|
| sqli | SQL 注入测试 |
| idor | IDOR 越权测试 |
| jwt | JWT 安全测试 |
| auth | 认证漏洞测试 |
| xss | XSS 测试 |
| ssrf | SSRF 测试 |
| all | 全部测试 |

## 输出格式

### 发现漏洞

| 漏洞类型 | 端点 | 严重程度 | 验证状态 | PoC |
|---------|------|---------|---------|-----|
| SQL注入 | /api/user?id=1 | HIGH | 已验证 | payload... |

### 详细分析

对每个漏洞提供：
1. **描述**: 漏洞的详细说明
2. **位置**: 具体的端点和参数
3. **验证步骤**: 如何验证漏洞存在
4. **PoC**: 具体的测试payload
5. **修复建议**: 如何修复该漏洞
</command-instruction>
