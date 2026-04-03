---
name: api-security-testing
description: 全自动 API 安全测试插件 - Playwright JS采集、API发现、漏洞检测、报告生成，内置赛博监工持续监督循环执行。Triggers on: API安全测试、漏洞扫描、渗透测试、API检测。当检测到安全测试任务时自动激活。
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
Phase 4: 验证与利用链构造
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
# 完整扫描
/api-security-testing scan https://target.com

# 快速测试
/api-security-testing test https://target.com/api/endpoint

# 开启赛博监工
/api-security-testing hook on

# 查看状态
/api-security-testing status
```

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

### 外部测试引擎

如需使用独立的 Python 测试引擎，可以调用 Claude Code 版本的 core 模块：

```bash
# 克隆仓库
git clone https://github.com/steveopen1/skill-play.git

# 进入测试引擎目录
cd agent-plugins/CLAUDE-CODE/api-security-testing

# 安装依赖
pip install playwright requests beautifulsoup4
playwright install chromium

# 运行测试
python3 core/deep_api_tester_v55.py https://target.com/ output.md
```

### 赛博监工控制

```bash
/cyber-supervisor on    # 开启监督
/cyber-supervisor off   # 关闭监督
/cyber-supervisor status  # 查看状态
/cyber-supervisor reset  # 重置状态
```

### 注意事项

- 仅用于合法授权的安全测试
- 测试前确保有书面授权
- 敏感操作需二次确认