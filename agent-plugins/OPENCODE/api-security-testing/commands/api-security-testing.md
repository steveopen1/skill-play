---
description: API Security Testing - API 安全测试主入口
agent: build
---

## API Security Testing - API 安全测试

执行 API 安全测试、漏洞扫描、渗透测试。

### 可用命令

- `/api-security-testing-scan` - 完整扫描模式
- `/api-security-testing-test` - 针对特定端点快速测试
- `/api-security-testing-status` - 查看测试状态

### 核心能力

1. **Playwright JS 动态采集** - 无头浏览器执行，XHR/Fetch 拦截
2. **API 端点发现** - JS 解析、URL 模式提取
3. **漏洞检测** - SQLi、XSS、IDOR、敏感数据、安全头部
4. **赛博监工** - 自动监测进度，失败时压力升级

### 触发词

当用户提到以下关键词时自动激活：
- "API 安全测试"
- "漏洞扫描"
- "渗透测试"
- "检测 API 漏洞"

### 报告输出

生成 Markdown 格式测试报告，包含端点列表、漏洞详情、利用链、修复建议。

### 注意

仅用于合法授权的安全测试，测试前确保有书面授权。