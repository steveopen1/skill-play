# Security Testing - 渗透测试 Payload 知识库

符合 OpenCode Skill 规范的渗透测试 Payload 知识库。

## 目录结构

```
security-testing/
├── .opencode/
│   └── skills/
│       └── security-testing/
│           └── SKILL.md         # OpenCode Skill 入口
├── data/                         # Payload 知识库
│   ├── web/                    # Web 漏洞
│   │   ├── sqli/              # SQL 注入
│   │   ├── xss/               # XSS
│   │   ├── ssrf/              # SSRF
│   │   ├── rce/               # RCE
│   │   └── ...
│   ├── intranet/               # 内网渗透
│   └── tools/                  # 工具命令
└── README.md
```

## OpenCode Skill

### 安装

复制到项目 `.opencode` 目录：

```bash
cp -r security-testing/.opencode <project>/
```

或复制到全局：

```bash
cp -r security-testing/.opencode ~/.config/opencode/
```

### 使用方式

在 OpenCode 中使用 skill：

```
skill({ name: "security-testing" })
```

加载 Skill 后，使用 `@` 语法引用 Payload 文件：

```
@data/web/sqli/mysql.md        # MySQL 注入
@data/web/xss/waf-bypass.md     # XSS WAF 绕过
@data/tools/nmap.md              # Nmap 命令
```

## 漏洞类别

### Web 漏洞 (data/web/)

| 类别 | 路径 | 说明 |
|------|------|------|
| SQL 注入 | `sqli/` | MySQL/MSSQL/Oracle/PostgreSQL |
| XSS | `xss/` | 反射/存储/DOM 型 |
| SSRF | `ssrf/` | 服务端请求伪造 |
| RCE | `rce/` | 远程代码执行 |
| LFI | `lfi/` | 文件包含 |
| XXE | `xxe/` | XML 实体注入 |
| SSTI | `ssti/` | 模板注入 |
| JWT | `jwt/` | JSON Web Token |

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

## 示例

### SQL 注入测试

```markdown
skill({ name: "security-testing" })

使用以下 Payload:
@data/web/sqli/mysql.md        # MySQL 注入
@data/web/sqli/waf-bypass.md   # WAF 绕过
@data/web/sqli/attack-chain.md # 攻击链
```

### XSS WAF 绕过

```markdown
@data/web/xss/waf-bypass.md
```

## 重要

- 仅用于授权渗透测试
- 遵循网络安全法律法规
