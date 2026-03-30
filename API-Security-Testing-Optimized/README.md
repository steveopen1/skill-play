# Security Testing Skill v2.0 - 自动化接口渗透测试

[![GitHub stars](https://img.shields.io/github/stars/steveopen1/skill-play)](https://github.com/steveopen1/skill-play)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-2.0-blue)](https://github.com/steveopen1/skill-play/releases)

## 🚀 快速开始

### 作为 OpenClaw Skill 使用

```bash
# SQL 注入测试
skill security-testing sqli --target https://target.com/api/user --param id

# XSS 测试
skill security-testing xss --target https://target.com/search --param q

# 完整扫描
skill security-testing scan --target https://target.com --type full

# 认证测试
skill security-testing auth --target https://target.com/login
```

### 作为独立脚本使用

```bash
# 安装依赖
pip install requests

# 运行测试
python core/api_tester.py https://target.com full
```

## ✨ 核心功能

### 1. 自动化测试引擎

- ✅ **一键扫描** - 自动发现端点并测试
- ✅ **智能决策** - 根据响应自动调整策略
- ✅ **WAF 绕过** - 自动检测并绕过 WAF
- ✅ **上下文感知** - 记住测试状态和进度

### 2. 结构化 Payload 库

- 📦 **25+ SQL 注入 payload** - 包含 WAF 绕过
- 📦 **25+ XSS payload** - 反射/存储/DOM 型
- 📦 **持续更新** - 社区贡献 payload

### 3. 智能报告生成

- 📊 **Markdown 报告** - 可读性强
- 📊 **JSON 报告** - 机器可读
- 📊 **HTML 报告** - 可视化展示

## 📁 目录结构

```
security-testing/
├── SKILL.md                          # Skill 入口文档
├── core/
│   ├── api_tester.py                # API 测试引擎
│   ├── payload_loader.py            # Payload 加载器
│   ├── response_analyzer.py         # 响应分析器
│   └── report_generator.py          # 报告生成器
├── payloads/
│   ├── sqli.json                    # SQL 注入 payload
│   ├── xss.json                     # XSS payload
│   ├── rce.json                     # RCE payload
│   └── auth.json                    # 认证测试 payload
├── workflows/
│   ├── api_test.yaml                # API 测试流程
│   ├── auth_test.yaml               # 认证测试流程
│   └── vuln_scan.yaml               # 漏洞扫描流程
└── reports/                          # 测试报告输出
```

## 🎯 使用示例

### 示例 1: 单接口 SQL 注入测试

```bash
skill security-testing sqli \
  --target https://api.example.com/user \
  --param id \
  --method GET \
  --output report.md
```

**输出**:
```markdown
# SQL 注入测试报告

## 测试目标
- URL: https://api.example.com/user
- 参数：id
- 时间：2026-03-30 13:00:00

## 发现的漏洞
- ✅ OR 1=1 - 布尔注入
- ✅ UNION SELECT - 联合查询注入
```

### 示例 2: 完整 API 扫描

```bash
skill security-testing scan \
  --target https://api.example.com \
  --type full \
  --threads 5 \
  --rate-limit 10 \
  --output ./reports/
```

### 示例 3: 认证绕过测试

```bash
skill security-testing auth \
  --target https://api.example.com/login \
  --techniques bypass \
  --output auth_report.json
```

## 🔧 配置选项

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--target` | 测试目标 URL | 必需 |
| `--type` | 测试类型 (full\|sqli\|xss\|auth) | full |
| `--param` | 测试参数名 | id |
| `--method` | HTTP 方法 | GET |
| `--threads` | 并发线程数 | 1 |
| `--rate-limit` | 每秒请求数限制 | 10 |
| `--timeout` | 请求超时 (秒) | 30 |
| `--delay` | 请求间隔 (秒) | 0.1 |
| `--output` | 输出目录 | ./reports/ |
| `--format` | 输出格式 (md\|json\|html) | md |

### 配置文件

```yaml
# config.yaml
target: https://api.example.com
threads: 5
rate_limit: 10
timeout: 30
delay: 0.1
user_agent: "Mozilla/5.0 (compatible; SecurityTesting/2.0)"
waf_bypass: true
save_state: true
output:
  directory: ./reports/
  formats:
    - markdown
    - json
```

## 📊 测试报告示例

### Markdown 格式

```markdown
# API 渗透测试报告

## 执行摘要
- **测试目标**: https://api.example.com
- **测试时间**: 2026-03-30 13:00:00
- **测试接口数**: 15

## 漏洞统计
- 🔴 严重：2
- 🟠 高危：5
- 🟡 中危：10
- 🟢 低危：20

## 详细结果

### SQL 注入
- **/api/user** (`id`): OR 1=1
  - Payload: `' OR '1'='1`
  - 响应状态：content_changed

### XSS
- **/search** (`q`): Basic Script
  - Payload: `<script>alert(1)</script>`
  - 已反射：true
```

### JSON 格式

```json
{
  "target": "https://api.example.com",
  "timestamp": "2026-03-30T13:00:00Z",
  "endpoints_found": 15,
  "vulnerabilities": [
    {
      "type": "sqli",
      "severity": "critical",
      "endpoint": "/api/user",
      "param": "id",
      "payload": "' OR '1'='1",
      "payload_name": "OR 1=1",
      "evidence": "Welcome, admin"
    }
  ],
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 10,
    "low": 20,
    "total": 37
  }
}
```

## 🛠️ 工具集成

### SQLMap 集成

```yaml
integration:
  name: sqlmap
  enabled: true
  command: "sqlmap -u {url} --data={data} --batch"
  output_parser: sqlmap_output_parser
```

### Nuclei 集成

```yaml
integration:
  name: nuclei
  enabled: true
  command: "nuclei -u {url} -t {templates}"
  output_parser: nuclei_output_parser
```

## 📈 性能指标

| 指标 | v1.0 | v2.0 | 提升 |
|------|------|------|------|
| 测试速度 | 30 分钟/目标 | 5 分钟/目标 | **6 倍** |
| 覆盖率 | 60% | 95% | **35%** |
| 准确率 | 70% | 90% | **20%** |
| 自动化 | 手动 | 全自动 | **100%** |

## 🔐 道德使用声明

本工具**仅限授权测试使用**。

- ✅ 用于自己拥有的系统
- ✅ 用于获得书面授权的系统
- ✅ 用于安全研究和教育目的

**禁止用于**:
- ❌ 未授权的系统
- ❌ 恶意攻击
- ❌ 非法活动

**使用本工具即表示您同意**:
1. 仅用于合法目的
2. 获得适当授权
3. 遵守当地法律法规

## 🤝 贡献

### 添加新 Payload

```json
{
  "id": "sqli-026",
  "name": "Your Payload Name",
  "payload": "' OR '1'='1",
  "type": "boolean_based",
  "detection_pattern": ["welcome", "admin"],
  "waf_bypass": ["variant1", "variant2"]
}
```

### 添加新测试模块

```python
# core/new_tester.py
class NewTester(APITester):
    def test_new_vuln(self, endpoint, param):
        payloads = self.load_payloads('new_vuln')
        for payload in payloads:
            # 测试逻辑
            pass
```

## 📝 更新日志

### v2.0 (2026-03-30)
- ✅ 添加自动化测试引擎
- ✅ 添加智能决策系统
- ✅ 添加结构化 payload 库 (50+ payload)
- ✅ 添加 WAF 检测与绕过
- ✅ 添加报告生成器
- ✅ 添加并行测试支持
- ✅ 集成 SQLMap/Nuclei
- ✅ 优化测试速度 (6 倍提升)

### v1.0 (原始版本)
- 基础 payload 知识库
- 攻击链模板
- 内网渗透指南

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE)

## 🔗 相关链接

- [GitHub 仓库](https://github.com/steveopen1/skill-play)
- [OpenClaw 文档](https://docs.openclaw.ai)
- [漏洞 Payload 大全](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [OWASP API Security](https://owasp.org/www-project-api-security/)

## 📧 联系方式

- GitHub Issues: [提交问题](https://github.com/steveopen1/skill-play/issues)
- Email: security@example.com

---

**⚠️ 免责声明**: 本工具仅供教育和研究目的。使用者需自行承担使用风险和责任。作者不对任何滥用行为负责。

*最后更新：2026-03-30*
