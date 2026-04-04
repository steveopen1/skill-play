# Security Testing - 渗透测试 Payload 知识库

多平台渗透测试 Payload 知识库。

## 目录结构

```
security-testing/
├── OPENCODE/                      # OpenCode 版本
│   └── security-testing/
│       ├── SKILL.md             # OpenCode Skill
│       └── data/                 # Payload 数据
│
├── CLAUDE-CODE/                   # Claude Code 版本
│   └── security-testing/
│       ├── SKILL.md             # Claude Code Skill
│       └── data/                 # Payload 数据
│
└── README.md
```

## OpenCode 安装

```bash
cp -r security-testing/OPENCODE/security-testing <project>/.opencode/skills/
```

## Claude Code 安装

```bash
cp -r security-testing/CLAUDE-CODE/security-testing <project>/.claude/skills/
```

## 使用方式

### OpenCode

```markdown
skill({ name: "security-testing" })

@data/web/sqli/mysql.md
@data/web/xss/waf-bypass.md
```

### Claude Code

```markdown
读取 data/web/sqli/mysql.md
读取 data/web/xss/waf-bypass.md
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
| JWT | `jwt/` |
| CSRF | `csrf.md` |
| API | `api.md` |

### 内网渗透 (data/intranet/)

| 阶段 | 路径 |
|------|------|
| 信息收集 | `recon/` |
| 凭证窃取 | `cred theft/` |
| 横向移动 | `lateral/` |
| 权限提升 | `privesc/` |

### 工具 (data/tools/)

| 工具 | 路径 |
|------|------|
| Nmap | `nmap.md` |
| SQLMap | `sqlmap.md` |
| Metasploit | `metasploit.md` |
| Hydra | `hydra.md` |

## 重要

- 仅用于授权渗透测试
- 遵循网络安全法律法规