---
description: 赛博监工控制 - 开启/关闭自动监督
agent: build
---

赛博监工 (Cyber Supervisor) 控制命令。

## 功能
- **on** - 开启赛博监工：启动自动循环测试监督
- **off** - 关闭赛博监工：停止自动监督
- **status** - 查看当前监工状态
- **reset** - 重置监工状态

## 监工触发条件
- tool.execute.after: 检测失败次数
- session.idle: 检查测试进度
- 发现新漏洞时自动深度测试

## 压力等级
| 等级 | 失败次数 | 动作 |
|------|----------|------|
| L1 | 2次 | 切换方法 |
| L2 | 3次 | 深度分析 |
| L3 | 5次 | 7点检查清单 |
| L4 | 7次+ | 绝望模式 |

## 使用方式
```
/api-security-testing hook on
/api-security-testing hook off
/api-security-testing hook status
```