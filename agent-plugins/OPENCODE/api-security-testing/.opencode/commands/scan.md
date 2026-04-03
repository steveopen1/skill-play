---
description: API Security Testing - 完整扫描模式
agent: build
---

执行完整的 API 安全测试扫描流程：

## Phase 1: JS 动态采集
- Playwright 无头浏览器执行
- 动态路由发现
- XHR/Fetch 请求拦截

## Phase 2: API 端点发现
- JS 文件解析
- URL 模式提取
- 智能去重

## Phase 3: 漏洞检测
- SQL 注入测试
- XSS 测试
- IDOR 测试
- 敏感数据暴露
- 安全头部检查

## Phase 4: 验证与报告
- 漏洞验证
- 利用链构造
- Markdown 报告生成

## 执行
加载 SKILL.md 获取详细测试流程指导，然后开始执行完整扫描。