---
description: 查看 API 安全测试状态
agent: build
---

查看当前 API 安全测试的状态和进度。

## 状态信息
- **测试进度**: 已完成/总计 端点
- **发现漏洞**: 按严重程度分类 (HIGH/MEDIUM/LOW)
- **监工状态**: 开启/关闭
- **失败计数**: 当前失败次数
- **压力等级**: L0-L4

## 输出格式
```
[APSEC Status]
Progress: 45/76 endpoints
Vulnerabilities: 3 HIGH, 5 MEDIUM, 2 LOW
Cyber Supervisor: ON (L2)
Failures: 2
```