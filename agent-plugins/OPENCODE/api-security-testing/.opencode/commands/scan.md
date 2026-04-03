---
description: API Security Testing - 完整扫描模式
agent: build
---

执行完整的 API 安全测试扫描流程。

## 自动激活赛博监工

**重要**：执行扫描时，必须先激活赛博监工。立即调用：

```
/cyber-supervisor on
```

这将开启自动监督，监控测试进度和失败次数。

## 测试流程

### Phase 1: JS 动态采集
- Playwright 无头浏览器执行
- 动态路由发现
- XHR/Fetch 请求拦截

### Phase 2: API 端点发现
- JS 文件解析
- URL 模式提取
- 智能去重

### Phase 3: 漏洞检测
- SQL 注入测试
- XSS 测试
- IDOR 测试
- 敏感数据暴露
- 安全头部检查

### Phase 4: 验证与报告
- 漏洞验证
- 利用链构造
- Markdown 报告生成

## 执行步骤

1. **激活赛博监工**：`/cyber-supervisor on`
2. **开始扫描**：按照上述流程执行测试
3. **自动监督**：赛博监工会自动监测进度和失败
4. **生成报告**：测试完成后自动生成 Markdown 报告