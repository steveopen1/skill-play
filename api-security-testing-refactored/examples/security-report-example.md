# 深度 API 渗透测试报告

## 执行摘要

- **测试目标**: http://[TARGET]
- **测试时间**: [TEST_DATE]
- **测试工具**: [TOOL_NAME]

## 发现统计

| 类型 | 数量 |
|------|------|
| JS 文件 | 15 |
| API 端点 | 164 |
| 漏洞数量 | 9 |

## API 端点清单 (164个)

```
GET /dist
GET /basic-platform/licence/authentication
GET /a/b
GET /a/i
GET /group
GET /named
GET /api/v1/map
GET /script
GET /redirect
GET /flowable/api/v1/process/read/xml
GET /oa/task/flow/record
GET /flowable/api/v1/process/complete
GET /oa/detail/common/process/instance
GET /oa/detail/common/business
GET /oa/approval/common/start
GET /oa/approval/common/save/draft
GET /oa/attachment/query
GET /oa/attachment/upload
GET /system/config/list
GET /system/config
GET /system/config/configKey
GET /system/config/refreshCache
GET /auth/login
GET /auth/external/login
GET /auth/refresh
GET /system/user/getInfo
GET /auth/logout
...
```

## 漏洞详情

### Unauthorized Access - 配置接口未授权

- **严重程度**: HIGH
- **端点**: http://[TARGET]/system/config/list
- **证据**: Status: 200, 无需认证即可访问系统配置
- **影响**: 攻击者可获取系统敏感配置信息
- **修复建议**: 对配置接口添加认证校验

### Unauthorized Access - 系统配置泄露

- **严重程度**: HIGH
- **端点**: http://[TARGET]/system/config
- **证据**: Status: 200
- **影响**: 系统配置信息泄露
- **修复建议**: 添加权限验证

### CORS配置错误

- **严重程度**: MEDIUM
- **端点**: 多个API端点
- **证据**: Access-Control-Allow-Origin: *
- **影响**: 可能被恶意页面利用获取数据
- **修复建议**: 限制CORS白名单

## 利用链分析

```
信息收集 → 发现/system/config接口 → 无需认证访问配置 → 获取数据库连接信息 → 横向移动
```

## 修复建议

| 优先级 | 漏洞 | 修复方案 |
|--------|------|----------|
| 高 | 配置接口未授权 | 添加JWT认证校验 |
| 中 | CORS配置错误 | 限制允许的Origin |
| 低 | 敏感信息泄露 | 移除响应中的敏感字段 |
