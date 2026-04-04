---
name: security-testing
description: 渗透测试 Payload 知识库 - SQL注入、XSS、SSRF、RCE、LFI 等漏洞 Payload，WAF绕过和攻击链模板。使用 @data/xxx 引用文件。
---

# Security Testing - 渗透测试 Payload 知识库

## 使用方式

通过 `@data/xxx` 引用 `data/` 目录下的 Payload 文件。

## SQL 注入 (data/web/sqli/)

| 文件 | 说明 |
|------|------|
| `data/web/sqli/mysql.md` | MySQL 注入 |
| `data/web/sqli/mssql.md` | MSSQL 注入 |
| `data/web/sqli/oracle.md` | Oracle 注入 |
| `data/web/sqli/postgresql.md` | PostgreSQL 注入 |
| `data/web/sqli/mongodb.md` | MongoDB 注入 |
| `data/web/sqli/redis.md` | Redis 注入 |
| `data/web/sqli/blind.md` | 盲注技术 |
| `data/web/sqli/time-blind.md` | 时间盲注 |
| `data/web/sqli/error-based.md` | 报错注入 |
| `data/web/sqli/union.md` | 联合查询 |
| `data/web/sqli/waf-bypass.md` | WAF 绕过 |
| `data/web/sqli/attack-chain.md` | 攻击链 |

## XSS (data/web/xss/)

| 文件 | 说明 |
|------|------|
| `data/web/xss/xss-detail.md` | XSS 详细分类 |
| `data/web/xss/waf-bypass.md` | WAF 绕过 |
| `data/web/xss/attack-chain.md` | 攻击链 |

## SSRF (data/web/ssrf/)

| 文件 | 说明 |
|------|------|
| `data/web/ssrf/ssrf-detail.md` | SSRF 详细 |
| `data/web/ssrf/waf-bypass.md` | WAF 绕过 |
| `data/web/ssrf/attack-chain.md` | 攻击链 |

## RCE (data/web/rce/)

| 文件 | 说明 |
|------|------|
| `data/web/rce/rce-detail.md` | RCE 详细 |
| `data/web/rce/waf-bypass.md` | WAF 绕过 |
| `data/web/rce/attack-chain.md` | 攻击链 |

## LFI (data/web/lfi/)

| 文件 | 说明 |
|------|------|
| `data/web/lfi/lfi-detail.md` | LFI 详细 |
| `data/web/lfi/waf-bypass.md` | WAF 绕过 |
| `data/web/lfi/attack-chain.md` | 攻击链 |

## 其他漏洞

| 文件 | 说明 |
|------|------|
| `data/web/csrf.md` | CSRF |
| `data/web/auth.md` | 认证漏洞 |
| `data/web/auth-detail.md` | 认证漏洞详细 |
| `data/web/jwt.md` | JWT 安全 |
| `data/web/jwt-detail.md` | JWT 详细 |
| `data/web/api.md` | API 安全 |
| `data/web/api-detail.md` | API 详细 |
| `data/web/websocket.md` | WebSocket 安全 |
| `data/web/smuggling.md` | HTTP 请求走私 |
| `data/web/biz-logic.md` | 业务逻辑 |
| `data/web/redirect.md` | 开放重定向 |

## 内网渗透 (data/intranet/)

| 文件 | 说明 |
|------|------|
| `data/intranet/recon/intranet-detail.md` | 信息收集 |
| `data/intranet/cred theft/credential-theft-detail.md` | 凭证窃取 |
| `data/intranet/lateral/lateral-detail.md` | 横向移动 |
| `data/intranet/privesc/privesc-detail.md` | 权限提升 |
| `data/intranet/tunnel/tunnel-detail.md` | 隧道代理 |
| `data/intranet/ad-attack/ad-attack-detail.md` | 域渗透 |

## 工具 (data/tools/)

| 文件 | 说明 |
|------|------|
| `data/tools/nmap.md` | Nmap |
| `data/tools/sqlmap.md` | SQLMap |
| `data/tools/metasploit.md` | Metasploit |
| `data/tools/hydra.md` | Hydra |
| `data/tools/hashcat.md` | Hashcat |
| `data/tools/crackmapexec.md` | CrackMapExec |
| `data/tools/powershell.md` | PowerShell |
| `data/tools/reverse-shell.md` | 反向 Shell |

## 使用示例

需要进行 SQL 注入测试时：

```
1. 读取 @data/web/sqli/mysql.md 获取 MySQL Payload
2. 读取 @data/web/sqli/waf-bypass.md 获取绕过方法
3. 读取 @data/web/sqli/attack-chain.md 构造攻击链
```

## 重要

- 仅用于授权渗透测试
- 遵循网络安全法律法规