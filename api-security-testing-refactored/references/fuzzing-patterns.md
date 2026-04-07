# Fuzzing 字典

## API前缀字典

```python
common_api_prefixes = [
    # 协议/网关
    "/gateway", "/proxy", "/route", "/ingress",
    "/api-gateway", "/openapi", "/open/api",
    # 版本前缀
    "/v1", "/v2", "/v3", "/v4", "/v5",
    "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/api", "/graphql",
    # 管理后台
    "/admin", "/admin/api", "/manager", "/backend",
    "/backoffice", "/cms",
    # 业务模块
    "/user", "/users", "/member", "/members",
    "/order", "/orders", "/trade", "/transaction",
    "/product", "/goods", "/shop", "/store",
    "/payment", "/pay", "/finance", "/account",
    "/file", "/upload", "/oss", "/storage",
    "/message", "/notify", "/sms", "/email",
    "/admin", "/authority", "/system", "/config",
    # 微服务
    "/service", "/services", "/rpc", "/grpc",
    "/auth", "/oauth", "/sso", "/cas",
    # 移动端
    "/mobile", "/app", "/ios", "/android",
    "/miniapp", "/wechat", "/applet",
]
```

## API端点字典

```python
common_api_endpoints = [
    # 通用CRUD
    "login", "logout", "register", "list", "add", "delete", "modify",
    "getList", "getListOfPage", "detail", "getInfo", "profile",
    # 用户相关
    "user", "user/list", "user/add", "user/delete", "user/modify",
    "user/profile", "user/restPassword", "user/enable", "user/disable",
    # 角色权限
    "role", "role/list", "role/add", "role/delete", "role/modify",
    "menu", "menu/list", "menu/add", "menu/delete", "menu/modify",
    # 文件操作
    "file", "upload", "download", "import", "export",
    "imgUpload", "avatar", "attachment",
]
```

## Fuzzing测试流程

```python
for prefix in common_api_prefixes:
    for endpoint in common_api_endpoints:
        url = target + prefix + "/" + endpoint
        response = requests.get(url)
        # 记录返回200的接口
```

## API根路径探测

```python
root_paths = [
    "/", "/login", "/auth", "/oauth", "/sso", "/cas",
    "/health", "/healthz", "/ready", "/status", "/info",
    "/metrics", "/ping", "/actuator",
]

for path in root_paths:
    url = api_base + path
    response = requests.get(url)
    if "json" in response.headers.get("Content-Type", ""):
        # 发现可访问的接口
```

## 业务端点模板扩展

```
发现的模式: /{module}/{operation}
可能存在的端点:
- /{module}/list          → 列表查询
- /{module}/add          → 新增创建
- /{module}/modify       → 修改更新
- /{module}/delete       → 删除操作
- /{module}/detail       → 详情查看
- /{module}/getInfo      → 信息获取
- /{module}/export       → 导出数据
- /{module}/import       → 导入数据

RESTful风格:
- GET  /{resource}/{id}     → 获取详情
- PUT  /{resource}/{id}     → 完整更新
- DELETE /{resource}/{id}   → 删除资源
- PATCH /{resource}/{id}   → 部分更新
```

## 非通用base_path字典

```python
extended_base_paths = [
    # 协议/网关
    "/gateway", "/proxy", "/route", "/ingress",
    "/api-gateway", "/openapi", "/open/api",
    # 版本前缀
    "/v1", "/v2", "/v3", "/v4", "/v5",
    "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/api", "/graphql",
    # 管理后台
    "/admin", "/manager", "/manage", "/console",
    "/backend", "/backoffice", "/cms",
    # 业务模块
    "/user", "/users", "/member", "/members",
    "/order", "/orders", "/trade", "/transaction",
    "/product", "/goods", "/shop", "/store",
    "/payment", "/pay", "/finance", "/account",
    "/file", "/upload", "/oss", "/storage",
    "/message", "/notify", "/sms", "/email",
    "/admin", "/authority", "/system", "/config",
    # 微服务
    "/service", "/services", "/rpc", "/grpc",
    "/auth", "/oauth", "/sso", "/cas",
    # 移动端
    "/mobile", "/app", "/ios", "/android",
    "/miniapp", "/wechat", "/applet",
]
```
