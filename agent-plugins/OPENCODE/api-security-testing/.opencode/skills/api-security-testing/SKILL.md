---
name: api-security-testing
description: 全自动 API 安全测试插件 - Playwright JS采集、API发现、漏洞检测、报告生成，内置赛博监工持续监督循环执行。Triggers on: API安全测试、漏洞扫描、渗透测试、API检测。
license: MIT
compatibility: opencode
---

## API Security Testing - API 安全测试

### 核心能力

1. **Playwright 强制 JS 动态采集**
   - 无头浏览器执行 JavaScript
   - 动态路由发现
   - XHR/Fetch 请求拦截

2. **API 端点智能发现**
   - JS 文件解析提取 API 路径
   - URL 模式识别与去重
   - 敏感端点识别

3. **漏洞检测**
   - SQL 注入 (SQLi)
   - XSS 跨站脚本
   - IDOR 水平越权
   - 敏感数据暴露
   - 安全头部检查

4. **赛博监工机制 (Cyber Supervisor)**
   - **自动激活**：执行扫描时自动开启监督
   - 监控测试进度 (Progress)
   - 检测失败次数 (Failure Count)
   - 触发压力升级 (L1-L4)
   - 决策是否继续循环

### 测试流程

```
Phase 1: JS 动态采集
    ↓
Phase 2: API 端点发现
    ↓
Phase 3: 漏洞检测
    ↓
Phase 4: 赛博监工验证与利用链构造
    ↓
Phase 5: 自动报告生成
```

### 命令使用

当用户提到以下关键词时自动激活：
- "API 安全测试"
- "漏洞扫描"
- "渗透测试"
- "检测 API 漏洞"
- `/api-security-testing`

### 执行命令

```bash
# 完整扫描 (自动激活赛博监工)
/api-security-testing scan https://target.com

# 快速测试
/api-security-testing test https://target.com/api/endpoint

# 查看状态
/api-security-testing status
```

### 赛博监工自动机制

**重要**：当执行扫描命令时，赛博监工**自动激活**，无需手动开启。

赛博监工自动执行以下操作：
1. **监听每次工具执行** - 检测失败、发现新漏洞
2. **压力升级** - 失败次数达到阈值时自动升级
3. **进度监控** - 进度过低时警告
4. **完成通知** - 测试完成时通知

### 压力升级机制

| 失败次数 | 等级 | 自动动作 |
|---------|------|---------|
| 2次 | L1 | 切换方法继续 |
| 3次 | L2 | 深度分析 |
| 5次 | L3 | 执行7点检查清单 |
| 7次+ | L4 | 绝望模式，拼死一搏 |

### 漏洞验证标准

| 严重程度 | 漏洞类型 | 验证方式 |
|----------|----------|----------|
| HIGH | SQL 注入 | 布尔盲注/时间盲注确认 |
| HIGH | 未授权访问 | 访问控制绕过测试 |
| MEDIUM | XSS | 反射/存储型确认 |
| MEDIUM | 敏感数据暴露 | 数据脱敏检查 |
| LOW | 安全头部缺失 | HTTP 头部分析 |

### 输出格式

自动生成 Markdown 格式测试报告，包含：
- 测试目标信息
- 发现的端点列表
- 漏洞详情（严重程度、位置、验证步骤）
- 利用链说明
- 修复建议

### 赛博监工控制

虽然默认自动激活，但仍支持手动控制：

```bash
/cyber-supervisor on    # 手动开启
/cyber-supervisor off   # 手动关闭
/cyber-supervisor status  # 查看状态
/cyber-supervisor reset  # 重置状态
```

### 注意事项

- 仅用于合法授权的安全测试
- 测试前确保有书面授权
- 敏感操作需二次确认