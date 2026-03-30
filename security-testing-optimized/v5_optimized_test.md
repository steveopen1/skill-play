# 深度 API 渗透测试报告 v5.0 (最终版)

## 执行摘要
- **测试目标**: http://49.65.100.160:6004
- **测试时间**: 2026-03-30 15:16:05
- **测试工具**: Deep API Tester v5.0

## 发现统计
| 类型 | 数量 |
|------|------|
| JS 文件 | 2 |
| API 端点 | 15 |
| 敏感信息 | 0 |
| 漏洞数量 | 0 |

## JS 文件
- `http://49.65.100.160:6004/js/chunk-vendors.a7e2efc2.js`
- `http://49.65.100.160:6004/js/app.61420c8c.js`

## API 端点
- `GET http://49.65.100.160:6004/users/add` (js_analysis_users_path)
- `GET http://49.65.100.160:6004/users/importRecord` (js_analysis_users_path)
- `GET http://49.65.100.160:6004/users/edit` (js_analysis_users_path)
- `GET http://49.65.100.160:6004/projects/add` (js_analysis_projects_path)
- `GET http://49.65.100.160:6004/projects/importRecord` (js_analysis_projects_path)
- `GET http://49.65.100.160:6004/projects/edit` (js_analysis_projects_path)
- `GET http://49.65.100.160:6004/organ/units/importRecord` (js_analysis_organ_path)
- `GET http://49.65.100.160:6004/organ/units` (js_analysis_organ_path)
- `GET http://49.65.100.160:6004/organ/experts/` (js_analysis_organ_path)
- `GET http://49.65.100.160:6004/organ/logs/` (js_analysis_organ_path)
- `GET http://49.65.100.160:6004/organ/units/department` (js_analysis_organ_path)
- `GET http://49.65.100.160:6004/organ/experts` (js_analysis_organ_path)
- `GET http://49.65.100.160:6004/organ/experts/major` (js_analysis_organ_path)
- `GET http://49.65.100.160:6004/organ/logs` (js_analysis_organ_path)
- `GET http://49.65.100.160:6004/organ/logs/major` (js_analysis_organ_path)
