---
description: "API 安全测试 Skill。Triggers on: '安全测试', '漏洞扫描', '渗透测试', 'API检测', '安全评估', '/api-security-testing'."
argument-hint: "[目标URL]"
---

## API Security Testing

加载 Skill: `skills/api-security-testing/SKILL.md`

### 快速开始

```
安全测试 https://target.com
```

### 支持的触发方式

```
# 基础扫描
安全测试 https://target.com
漏洞检测 https://target.com
渗透测试 https://target.com

# 完整流程
全流程测试 https://target.com
完整测试 https://target.com

# 使用命令
/api-security-testing:scan https://target.com
```

### 执行流程

参考 SKILL.md 中的完整流程：

1. **Phase 1**: 侦察与发现
2. **Phase 2**: 分析与分类
3. **Phase 3**: 漏洞测试
4. **Phase 4**: 验证与确认
5. **Phase 5**: 利用与报告

### 重要

- 必须确认目标有合法授权
- 参考 `references/` 目录下的漏洞知识库
