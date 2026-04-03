# 漏洞测试方法索引

## SQL注入测试

详见 [01-sqli-tests.md](01-sqli-tests.md)

覆盖：参数化查询、UNION、布尔盲注、时间盲注、报错注入

## 用户枚举测试

详见 [02-user-enum-tests.md](02-user-enum-tests.md)

覆盖：手机号枚举、邮箱枚举、用户ID遍历、登录响应差异

## JWT认证测试

详见 [03-jwt-tests.md](03-jwt-tests.md)

覆盖：alg:none伪造、签名不验证、敏感信息泄露、Token重放

## IDOR越权测试

详见 [04-idor-tests.md](04-idor-tests.md)

覆盖：水平越权、垂直越权、直接对象引用、ID加密绕过

## 敏感信息泄露

详见 [05-sensitive-data-tests.md](05-sensitive-data-tests.md)

覆盖：密码明文返回、Token泄露、配置信息暴露、日志敏感信息

## 业务逻辑漏洞

详见 [06-biz-logic-tests.md](06-biz-logic-tests.md)

覆盖：批量操作绕过、流程绕过、参数篡改、条件竞争

## 安全配置漏洞

详见 [07-security-config-tests.md](07-security-config-tests.md)

覆盖：CORS配置错误、CSRF令牌缺失、接口限流绕过、敏感接口暴露

## 暴力破解测试

详见 [08-brute-force-tests.md](08-brute-force-tests.md)

覆盖：无验证码、验证码可绕过、限流绕过、并发请求

## 漏洞关联联想

详见 [09-vulnerability-chains.md](09-vulnerability-chains.md)

覆盖：漏洞串联思路、攻击链构造、实际利用场景
