# 深度 API 渗透测试报告 v5.5 (完美版)

## 执行摘要
- **测试目标**: http://49.65.100.160:6004
- **测试时间**: 2026-03-30 15:17:16
- **测试工具**: Deep API Tester v5.5

## 发现统计
| 类型 | 数量 |
|------|------|
| JS 文件 | 2 |
| API 端点 | 76 |
| 漏洞数量 | 0 |

## JS 文件
- `http://49.65.100.160:6004/js/chunk-vendors.a7e2efc2.js`
- `http://49.65.100.160:6004/js/app.61420c8c.js`

## API 端点 (76 个)
- `GET http://49.65.100.160:6004/dist`
- `GET http://49.65.100.160:6004/script`
- `GET http://49.65.100.160:6004/personnelWeb/system/sysUser/importUserData`
- `GET http://49.65.100.160:6004/system/sysUser/exportUserTemplate`
- `GET http://49.65.100.160:6004/personnelWeb/file/upload`
- `GET http://49.65.100.160:6004/users/add`
- `GET http://49.65.100.160:6004/users/importRecord`
- `GET http://49.65.100.160:6004/personnelWeb/system/project/importProjectData`
- `GET http://49.65.100.160:6004/system/project/exportProjectTemplate`
- `GET http://49.65.100.160:6004/projects/add`
- `GET http://49.65.100.160:6004/projects/importRecord`
- `GET http://49.65.100.160:6004/personnelWeb/system/company/importCompanyData`
- `GET http://49.65.100.160:6004/system/company/exportCompanyTemplate`
- `GET http://49.65.100.160:6004/organ/units/importRecord`
- `GET http://49.65.100.160:6004/organ/units`
- `GET http://49.65.100.160:6004/organ/experts`
- `GET http://49.65.100.160:6004/organ/logs`
- `GET http://49.65.100.160:6004/system/sysUser/userInfo`
- `GET http://49.65.100.160:6004/smartmine/dictData/list`
- `GET http://49.65.100.160:6004/users/edit`
- `GET http://49.65.100.160:6004/projects/edit`
- `GET http://49.65.100.160:6004/organ/units/department`
- `GET http://49.65.100.160:6004/organ/experts/major`
- `GET http://49.65.100.160:6004/organ/logs/major`
- `GET http://49.65.100.160:6004/system/sysUser/page`
- `GET http://49.65.100.160:6004/system/sysUser`
- `GET http://49.65.100.160:6004/system/sysUser/register`
- `GET http://49.65.100.160:6004/system/sysUser/getUserById`
- `GET http://49.65.100.160:6004/system/company`
- `GET http://49.65.100.160:6004/system/company/list`
- `GET http://49.65.100.160:6004/system/company/page`
- `GET http://49.65.100.160:6004/system/company/parentCompany`
- `GET http://49.65.100.160:6004/system/projectParticipant/projectParticipant`
- `GET http://49.65.100.160:6004/system/department/page`
- `GET http://49.65.100.160:6004/system/department`
- `GET http://49.65.100.160:6004/system/project/page`
- `GET http://49.65.100.160:6004/system/project`
- `GET http://49.65.100.160:6004/system/project/getProjectById`
- `GET http://49.65.100.160:6004/system/major/list`
- `GET http://49.65.100.160:6004/system/major`
- `GET http://49.65.100.160:6004/system/major/page`
- `GET http://49.65.100.160:6004/system/majorUser/page`
- `GET http://49.65.100.160:6004/system/majorUser/associationMajorUser`
- `GET http://49.65.100.160:6004/system/majorUser`
- `GET http://49.65.100.160:6004/system/majorGroup/page`
- `GET http://49.65.100.160:6004/system/majorGroup`
- `GET http://49.65.100.160:6004/system/majorGroupUser/page`
- `GET http://49.65.100.160:6004/system/majorGroupUser/associationMajorGroupUser`
- `GET http://49.65.100.160:6004/system/majorGroupUser`
- `GET http://49.65.100.160:6004/system/majorUserRecord/page`
- `GET http://49.65.100.160:6004/system/majorGroupUserRecord/page`
- `GET http://49.65.100.160:6004/system/companyRecord/page`
- `GET http://49.65.100.160:6004/system/userRecord/page`
- `GET http://49.65.100.160:6004/system/role`
- `GET http://49.65.100.160:6004/system/role/list`
- `GET http://49.65.100.160:6004/system/role/{e`
- `GET http://49.65.100.160:6004/system/menu/list`
- `GET http://49.65.100.160:6004/system/role/authMenu/cancel`
- `GET http://49.65.100.160:6004/system/role/authUser/unallocatedList`
- `GET http://49.65.100.160:6004/system/role/authUser/allocatedList`
- `GET http://49.65.100.160:6004/system/role/authUser/selectAll`
- `GET http://49.65.100.160:6004/sms/sms/code`
- `GET http://49.65.100.160:6004/auth/smsLogin`
- `GET http://49.65.100.160:6004/auth/login`
- `GET http://49.65.100.160:6004/system/sysUser/rePassword`
- `GET http://49.65.100.160:6004/system/sysUser/rePasswordById`
- `GET http://49.65.100.160:6004/system/dict/data/type/{e`
- `GET http://49.65.100.160:6004/system/importRecord/page`
- `GET http://49.65.100.160:6004/home`
- `GET http://49.65.100.160:6004/login`
- `GET http://49.65.100.160:6004/role`
- `GET http://49.65.100.160:6004/changePassword`
- `GET http://49.65.100.160:6004/users`
- `GET http://49.65.100.160:6004/projects`
- `GET http://49.65.100.160:6004/platformLogin`
- `GET http://49.65.100.160:6004/personnelWeb`
