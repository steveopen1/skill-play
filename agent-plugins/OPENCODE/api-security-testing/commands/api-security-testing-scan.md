---
description: API Security Testing - 完整扫描模式
agent: build
---

执行完整的 API 安全测试扫描流程。

## 测试流程

1. Playwright 无头浏览器执行 JavaScript，采集动态 API 端点
2. XHR/Fetch 请求拦截，发现 API 路径
3. 漏洞检测：SQL注入、XSS、IDOR、敏感数据暴露、安全头部
4. 验证与报告：利用链构造、Markdown 格式报告

## 漏洞测试参考

使用 `@` 语法引用漏洞测试指南：

```
@agent-plugins/OPENCODE/api-security-testing/references/vulnerabilities/README.md
@agent-plugins/OPENCODE/api-security-testing/references/workflows.md
@agent-plugins/OPENCODE/api-security-testing/references/test-matrix.md
```

## 输出要求

生成 Markdown 格式安全测试报告，包含：
- 测试目标信息
- 发现的端点列表
- 漏洞详情（严重程度、位置、验证步骤）
- 利用链说明
- 修复建议

## 重要

- 仅用于合法授权的安全测试
- 必须确认用户拥有测试目标的合法授权
