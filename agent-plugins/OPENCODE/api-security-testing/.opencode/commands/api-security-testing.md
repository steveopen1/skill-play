---
description: API Security Testing - API 安全测试主入口
agent: build
---

## APSEC API 安全测试

APSEC = API Security Testing + 赛博监工 (Cyber Supervisor)

### 功能模式

- **scan** - 完整扫描：JS收集 → API发现 → 漏洞检测 → 报告生成
- **test** - 快速测试：针对特定端点进行深度测试
- **hook** - 开启赛博监工模式：自动循环监督测试进度
- **status** - 查看当前测试状态和进度

### 使用方式

```
/api-security-testing scan https://target.com
/api-security-testing test https://target.com/api/endpoint
/api-security-testing hook on
/api-security-testing status
```

### 执行流程

1. **Phase 1**: Playwright 强制 JS 动态采集
2. **Phase 2**: API 端点智能发现与去重
3. **Phase 3**: 漏洞检测 (SQLi/XSS/IDOR/敏感数据等)
4. **Phase 4**: 赛博监工验证与利用链构造
5. **Phase 5**: 自动报告生成

### 赛博监工机制

当开启 hook 模式后，赛博监工将自动：
- 监控测试进度 (Progress)
- 检测失败次数 (Failure Count)
- 触发压力升级 (L1-L4)
- 决策是否继续循环

### 无参数时

无参数或只有目标URL时，执行完整 scan 流程。

加载 `skills/api-security-testing/SKILL.md` 获取完整测试流程指导。