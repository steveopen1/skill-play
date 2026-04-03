---
description: API Security Testing - 快速测试模式
agent: build
---

针对特定 API 端点进行深度安全测试。

## 加载漏洞测试模板

@references/vulnerabilities/01-sqli-tests.md

@references/vulnerabilities/04-idor-tests.md

@references/vulnerabilities/05-sensitive-data-tests.md

@references/validation.md

## 测试范围
- SQL 注入 (SQLi)
- XSS 跨站脚本
- IDOR 水平越权
- 敏感数据暴露
- 认证绕过

## 执行步骤
1. 识别端点参数
2. 构建测试 payload
3. 执行测试用例
4. 验证漏洞存在
5. 生成测试报告