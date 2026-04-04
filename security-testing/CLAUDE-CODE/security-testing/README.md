# Security Testing - Claude Code 版本

Claude Code 渗透测试 Payload 知识库。

## 安装

```bash
cp -r security-testing/CLAUDE-CODE/security-testing <project>/.claude/skills/
```

## 使用方式

### 触发方式

当提到以下关键词时自动激活：
- SQL 注入、XSS、SSRF、RCE、LFI
- 渗透测试、Payload、WAF 绕过
- 攻击链、漏洞利用

### 读取 Payload

```
读取 data/web/sqli/mysql.md        # MySQL 注入
读取 data/web/xss/waf-bypass.md     # XSS WAF 绕过
读取 data/intranet/recon/intranet-detail.md  # 内网信息收集
```

## 漏洞类别

### Web 漏洞 (data/web/)

| 类别 | 路径 |
|------|------|
| SQL 注入 | `sqli/` |
| XSS | `xss/` |
| SSRF | `ssrf/` |
| RCE | `rce/` |
| LFI | `lfi/` |
| XXE | `xxe/` |
| SSTI | `ssti/` |

### 内网渗透 (data/intranet/)

| 阶段 | 路径 |
|------|------|
| 信息收集 | `recon/` |
| 横向移动 | `lateral/` |
| 权限提升 | `privesc/` |

### 工具 (data/tools/)

| 工具 | 路径 |
|------|------|
| Nmap | `nmap.md` |
| SQLMap | `sqlmap.md` |
| Metasploit | `metasploit.md` |

## 重要

- 仅用于授权渗透测试
- 遵循网络安全法律法规
