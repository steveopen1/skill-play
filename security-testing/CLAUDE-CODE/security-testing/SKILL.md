---
name: security-testing
description: 渗透测试 Payload 知识库。【触发词】SQL注入、XSS、SSRF、RCE、LFI、XXE、SSTI、CSRF、JWT、API安全、渗透测试、Payload、WAF绕过、攻击链。【内容】提供完整渗透测试 Payload 知识库，包括 Web漏洞、内网渗透、工具命令。覆盖 SQL注入、XSS、SSRF、RCE、LFI、XXE、SSTI 等漏洞的 Payload、WAF绕过和攻击链模板。【使用】读取 data/web/sqli/ 获取 SQL 注入 Payload；读取 data/web/xss/ 获取 XSS Payload；读取 data/tools/ 获取工具命令。
---

# Security Testing - 渗透测试 Payload 知识库

## 漏洞类别

### Web 漏洞 (data/web/)

| 类别 | 路径 | 说明 |
|------|------|------|
| SQL 注入 | `sqli/` | MySQL/MSSQL/Oracle/PostgreSQL/MongoDB/Redis |
| XSS | `xss/` | 反射型、存储型、DOM 型 |
| SSRF | `ssrf/` | 服务端请求伪造 |
| RCE | `rce/` | 远程代码执行 |
| LFI | `lfi/` | 文件包含 |
| XXE | `xxe/` | XML 实体注入 |
| SSTI | `ssti/` | 模板注入 |
| CSRF | `csrf.md` | 跨站请求伪造 |
| JWT | `jwt.md` | JSON Web Token |
| API 安全 | `api.md` | API 接口安全 |

### 内网渗透 (data/intranet/)

| 阶段 | 路径 | 说明 |
|------|------|------|
| 信息收集 | `recon/` | 目标探测、端口扫描 |
| 凭证窃取 | `cred theft/` | 密码抓取、Hash 传递 |
| 横向移动 | `lateral/` | 令牌窃取、远程服务 |
| 权限提升 | `privesc/` | 本地提权、Sudo 攻击 |
| 权限维持 | `persistence/` | 后门、计划任务 |
| 隧道代理 | `tunnel/` | 端口转发、SOCKS 代理 |
| 域渗透 | `ad-attack/` | AD 枚举、Kerberos 攻击 |

### 工具命令 (data/tools/)

| 工具 | 路径 | 说明 |
|------|------|------|
| Nmap | `nmap.md` | 端口扫描 |
| SQLMap | `sqlmap.md` | SQL 注入工具 |
| Metasploit | `metasploit.md` | 渗透框架 |
| Hydra | `hydra.md` | 暴力破解 |
| Hashcat | `hashcat.md` | Hash 破解 |
| CrackMapExec | `crackmapexec.md` | 内网横向 |
| PowerShell | `powershell.md` | Windows 命令 |

## 使用方式

### SQL 注入 Payload

读取以下文件获取 Payload：
- `data/web/sqli/mysql.md` - MySQL 注入
- `data/web/sqli/mssql.md` - MSSQL 注入
- `data/web/sqli/oracle.md` - Oracle 注入
- `data/web/sqli/waf-bypass.md` - WAF 绕过
- `data/web/sqli/attack-chain.md` - 攻击链

### XSS Payload

- `data/web/xss/xss-detail.md` - XSS 详细分类
- `data/web/xss/waf-bypass.md` - WAF 绕过
- `data/web/xss/attack-chain.md` - 攻击链

### 内网渗透

- `data/intranet/recon/intranet-detail.md` - 信息收集
- `data/intranet/lateral/lateral-detail.md` - 横向移动
- `data/intranet/privesc/privesc-detail.md` - 权限提升

## 重要

- 仅用于授权渗透测试
- 遵循网络安全法律法规
