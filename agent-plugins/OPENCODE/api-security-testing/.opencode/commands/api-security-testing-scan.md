---
description: API Security Testing - 完整扫描模式
agent: build
---

执行完整的 API 安全测试扫描流程。

## 加载测试流程

@references/workflows.md

## 加载漏洞测试指南

@references/vulnerabilities/README.md

## 加载测试矩阵

@references/test-matrix.md

## 加载报告模板

@references/report-template.md

## 执行步骤

1. **激活赛博监工**：`/cyber-supervisor on`
2. **Phase 1**: JS 动态采集 - Playwright 无头浏览器
3. **Phase 2**: API 端点发现 - JS 解析 + URL 提取
4. **Phase 3**: 漏洞检测 - SQLi/XSS/IDOR/敏感数据
5. **Phase 4**: 验证与报告 - 利用链 + Markdown 报告