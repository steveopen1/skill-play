# 深度 API 渗透测试报告 v3.5

## 执行摘要
- **测试目标**: http://49.65.100.160:6004
- **测试时间**: 2026-03-30 15:03:28
- **测试工具**: Deep API Tester v3.5
- **测试深度**: 3 层

## 发现统计
| 类型 | 数量 |
|------|------|
| JS 文件 | 2 |
| API 端点 | 25 |
| 捕获流量 | 7 |
| 敏感信息 | 4 |
| 登录凭证 | 0 |
| 漏洞数量 | 6 |

## JS 文件列表
- `http://49.65.100.160:6004/js/app.61420c8c.js`
- `http://49.65.100.160:6004/js/chunk-vendors.a7e2efc2.js`

## API 端点列表
- `GET /`
- `GET /changePassword`
- `GET /group`
- `GET /home`
- `GET /itemStyle.color`
- `GET /lineStyle.color`
- `GET /login`
- `GET /major`
- `GET /organ/experts`
- `GET /organ/logs`
- `GET /organ/units`
- `GET /organ/units/department`
- `GET /organ/units/importRecord`
- `GET /personnel`
- `GET /platformLogin`
- `GET /projects`
- `GET /projects/add`
- `GET /projects/edit`
- `GET /projects/importRecord`
- `GET /role`
- `GET /unit`
- `GET /users`
- `GET /users/add`
- `GET /users/edit`
- `GET /users/importRecord`

## 敏感信息
- **[HIGH]** token: `);if(a>-1){const e=u.get(...`
  - 来源：http://49.65.100.160:6004/js/app.61420c8c.js
- **[HIGH]** token: `)[1];u.set(...`
  - 来源：http://49.65.100.160:6004/js/app.61420c8c.js
- **[HIGH]** token: `);if(a>-1){const e=u.get(...`
  - 来源：http://49.65.100.160:6004/js/app.61420c8c.js
- **[HIGH]** token: `)[1];u.set(...`
  - 来源：http://49.65.100.160:6004/js/app.61420c8c.js

## 漏洞详情

### Sensitive Data Exposure
- **严重程度**: MEDIUM
- **端点**: http://49.65.100.160:6004/js/chunk-vendors.a7e2efc2.js
- **方法**: N/A
- **证据**: Found email in response

### Sensitive Data Exposure
- **严重程度**: MEDIUM
- **端点**: http://49.65.100.160:6004/js/chunk-vendors.a7e2efc2.js
- **方法**: N/A
- **证据**: Found credit_card in response

### Sensitive Data Exposure
- **严重程度**: HIGH
- **端点**: http://49.65.100.160:6004/js/app.61420c8c.js
- **方法**: N/A
- **证据**: );if(a>-1){const e=u.get(

### Sensitive Data Exposure
- **严重程度**: HIGH
- **端点**: http://49.65.100.160:6004/js/app.61420c8c.js
- **方法**: N/A
- **证据**: )[1];u.set(

### Sensitive Data Exposure
- **严重程度**: HIGH
- **端点**: http://49.65.100.160:6004/js/app.61420c8c.js
- **方法**: N/A
- **证据**: );if(a>-1){const e=u.get(

### Sensitive Data Exposure
- **严重程度**: HIGH
- **端点**: http://49.65.100.160:6004/js/app.61420c8c.js
- **方法**: N/A
- **证据**: )[1];u.set(
