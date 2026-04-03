# API Fuzzing 端点字典

## API 前缀

### 已发现的前缀模式
```
/api, /api/v1-v4, /api/admin, /api/authority, /api/system,
/rest, /rest/api, /webapi,
/auth, /oauth, /oauth2, /cas, /sso,
/admin, /admin/api, /manager, /backend,
/openapi, /open/api, /gateway, /proxy
```

### 前缀扩展规则

当发现 `/api/admin/xxx` 时，可尝试：
```
/api/authority/xxx
/api/system/xxx
/api/common/xxx
/api/v1/xxx, /api/v2/xxx, /api/v3/xxx
```

当发现 `/api/xxx` 时，可尝试：
```
/rest/api/xxx
/webapi/xxx
/auth/xxx
/oauth/xxx
```

## API 端点

### 通用 CRUD 端点
```
login, logout, register, list, add, delete, modify,
getList, getListOfPage, detail, getInfo, profile,
export, import, upload, download
```

### 用户管理端点
```
user, users, user/list, user/add, user/delete, user/modify,
user/profile, user/restPassword, user/enable, user/disable,
user/export, user/import, user/checkOnlyUser
```

### 角色权限端点
```
role, roles, role/list, role/add, role/delete, role/modify,
menu, menus, menu/list, menu/add, menu/delete, menu/modify,
permission, permissions, getUserPermission, getUserPermissionChild
```

### 订单/支付端点
```
order, orders, order/list, order/add, order/delete, order/modify,
pay, payment, pay/add, pay/callback, pay/notify,
refund, refunds, refund/list, refund/add
```

### 文件操作端点
```
file, files, upload, download, import, export,
imgUpload, avatar, attachment
```

### RESTful 风格端点
```
/{resource}/{id}           → GET 获取详情
/{resource}/{id}           → PUT 完整更新
/{resource}/{id}           → DELETE 删除
/{resource}/{id}           → PATCH 部分更新
/{resource}/{id}/profile  → 获取关联信息
/{resource}/{id}/stat      → 获取统计
```

## Fuzzing 策略

### 矩阵测试
```python
prefixes = ["/api", "/api/admin", "/api/authority", "/rest", "/auth"]
endpoints = ["login", "logout", "list", "add", "delete", "user", "role", "menu"]

for prefix in prefixes:
    for endpoint in endpoints:
        url = target + prefix + "/" + endpoint
        test(url)
```

### 根路径探测
```
/ipark                         → SPA前端
/ipark/v2/api-docs             → Swagger文档(需认证)
/ipark/doc.html                → Knife4j文档
/sys/getLoginQrcode             → 二维码登录
/sys/user/checkOnlyUser         → 用户查重
```

## 常见响应码含义

| code | 含义 |
|------|------|
| 200 | 成功 |
| 401 | 需要认证/token为空 |
| 403 | 权限不足 |
| 500 | 服务器错误 |
| 90004 | 登录失效/未授权 |
