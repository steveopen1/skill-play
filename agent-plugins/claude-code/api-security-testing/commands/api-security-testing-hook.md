---
description: "APSEC 赛博监工模式。/api-security-testing:hook [on|off|status]。Triggers on: '/api-security-testing:hook', '/api-security-testing hook', 'api-security-testing hook on', 'api-security-testing hook off'."
argument-hint: "[on|off|status]"
---

## APSEC 赛博监工模式

赛博监工 (Cyber Supervisor) 是一种自动化的 Agent 监督机制。

### 模式说明

- **on** - 开启赛博监工：启动自动循环测试监督
- **off** - 关闭赛博监工：停止自动监督
- **status** - 查看当前监工状态

### 监工触发条件

| 事件 | 触发条件 | 动作 |
|------|----------|------|
| PostToolUse | 发现新漏洞 | 自动深度测试 |
| PostToolUseFailure | 失败次数累积 | L1-L4 压力升级 |
| Stop | 进度 < 100% | 决策: 继续/停止 |

### 压力等级 (L1-L4)

- **L1**: 切换到完全不同方法
- **L2**: 搜索 + 读源码 + 3个假设
- **L3**: 执行7点检查清单
- **L4**: 绝望模式，拼死一搏

### 使用

```
/api-security-testing:hook on
/api-security-testing:hook off
/api-security-testing:hook status
/api-security-testing hook on
```