# 深度 API 渗透测试报告 v5.5 (完美版)

## 执行摘要
- **测试目标**: http://[TARGET]
- **测试时间**: 2026-04-01 07:43:54
- **测试工具**: Deep API Tester v5.5

## 发现统计
| 类型 | 数量 |
|------|------|
| JS 文件 | 15 |
| API 端点 | 164 |
| 漏洞数量 | 9 |

## JS 文件
- `http://[TARGET]/jquery.js`
- `http://[TARGET]/config.js`
- `http://[TARGET]/static/js/runtime.6189983e.js`
- `http://[TARGET]/static/js/chunk-echarts.d03bf505.js`
- `http://[TARGET]/static/js/chunk-elementUI.2395d8d8.js`
- `http://[TARGET]/static/js/chunk-vue.6c5afe5f.js`
- `http://[TARGET]/static/js/chunk-zrender-lib.663e0021.js`
- `http://[TARGET]/static/js/chunk-small-wei.27227356.js`
- `http://[TARGET]/static/js/chunk-libs.c18fc3ed.js`
- `http://[TARGET]/static/js/6707.47b66700.js`
- `http://[TARGET]/static/js/index.0d365cba.js`
- `http://[TARGET]/static/js/6250.39db9c37.js`
- `http://[TARGET]/static/js/7703.7aa21fa0.js`
- `http://[TARGET]/static/js/8798.13c5f408.js`
- `http://[TARGET]/static/js/2392.7d0980fd.js`

## API 端点 (164 个)
- `GET http://[TARGET]/dist`
- `GET http://172.16.77.188:8083/basic-platform/licence/authentication`
- `GET http://[TARGET]/a/b`
- `GET http://[TARGET]/a/i`
- `GET http://[TARGET]/group`
- `GET http://[TARGET]/named`
- `GET http://[TARGET]/api/v1/map`
- `GET http://[TARGET]/script`
- `GET http://[TARGET]/redirect`
- `GET http://[TARGET]/flowable/api/v1/process/read/xml`
- `GET http://[TARGET]/oa/task/flow/record`
- `GET http://[TARGET]/flowable/api/v1/process/complete`
- `GET http://[TARGET]/oa/detail/common/process/instance`
- `GET http://[TARGET]/oa/detail/common/business`
- `GET http://[TARGET]/oa/approval/common/start`
- `GET http://[TARGET]/oa/approval/common/save/draft`
- `GET http://[TARGET]/oa/attachment/query`
- `GET http://[TARGET]/oa/attachment/upload`
- `GET http://[TARGET]/oa/attachment`
- `GET http://[TARGET]/oa/system/users`
- `GET http://[TARGET]/oa/system/depts`
- `GET http://[TARGET]/oa/task/node/cat`
- `GET http://[TARGET]/oa/leave/list/date`
- `GET http://[TARGET]/report/bigScreen/viewer`
- `GET http://[TARGET]/user/profile`
- `GET http://[TARGET]/file/upload`
- `GET http://[TARGET]/file/file-minio/object/startUpload`
- `GET http://[TARGET]/file/file-minio/object/merge`
- `GET http://[TARGET]/report/gaeaDict/select`
- `GET http://[TARGET]/report/file/upload`
- `GET http://[TARGET]/resource/info/list`
- `GET http://[TARGET]/resource/info/manageList`
- `GET http://[TARGET]/resource/info/listByAlgo`
- `GET http://[TARGET]/resource/info/ipScan`
- `GET http://[TARGET]/resource/info/confirm`
- `GET http://[TARGET]/resource/info`
- `GET http://[TARGET]/resource/info/logicDelete`
- `GET http://[TARGET]/resource/info/recentSearch`
- `GET http://[TARGET]/resource/info/deviceSummary`
- `GET http://[TARGET]/resource/info/stopIpScan`
- `GET http://[TARGET]/resource/info/import/detail`
- `GET http://[TARGET]/resource/info/update`
- `GET http://[TARGET]/resource/info/updateBatch`
- `GET http://[TARGET]/system/record/applicantList`
- `GET http://[TARGET]/system/record/approverList`
- `GET http://[TARGET]/system/record/appList`
- `GET http://[TARGET]/system/desktop/application/desktop`
- `GET http://[TARGET]/system/desktop/application`
- `GET http://[TARGET]/system/app/detail`
- `GET http://[TARGET]/system/record`
- `GET http://[TARGET]/system/record/followUp`
- `GET http://[TARGET]/system/record/withDraw`
- `GET http://[TARGET]/system/record/review`
- `GET http://[TARGET]/system/record/reviewCount`
- `GET http://[TARGET]/msgcenter/template/list`
- `GET http://[TARGET]/msgcenter/template`
- `GET http://[TARGET]/msgcenter/content/list`
- `GET http://[TARGET]/msgcenter/content`
- `GET http://[TARGET]/msgcenter/api/push/selectByUserId`
- `GET http://[TARGET]/msgcenter/api/push/selectByTableName`
- `GET http://[TARGET]/lib/theme-chalk/index.css`
- `GET http://[TARGET]/system/dict/data/list`
- `GET http://[TARGET]/system/dict/data`
- `GET http://[TARGET]/system/dict/data/type`
- `GET http://[TARGET]/report/gaeaDict/all`
- `GET http://[TARGET]/report/bigScreen/designer`
- `GET http://[TARGET]/report/excelreport/viewer`
- `GET http://[TARGET]/report/excelreport/designer`
- `GET http://[TARGET]/redirect/:path(.*)`
- `GET http://[TARGET]/behaviorTaskManage/behaviorTaskReal`
- `GET http://[TARGET]/behaviorTaskManage/behaviorSubTaskReal`
- `GET http://[TARGET]/eventAlarm/eventAlarmVideoGroup`
- `GET http://[TARGET]/eventAlarm/rEventAlarmVideoGroup`
- `GET http://[TARGET]/eventAlarm/event_alarm_conf`
- `GET http://[TARGET]/report/FormStatistics`
- `GET http://[TARGET]/report/reportStatistical`
- `GET http://[TARGET]/subscribe/HikvisionConfig`
- `GET http://[TARGET]/report/dsf`
- `GET http://[TARGET]/report/errorlog`
- `GET http://[TARGET]/form/detail/:cFormKey`
- `GET http://[TARGET]/system/user-auth`
- `GET http://[TARGET]/system/user`
- `GET http://[TARGET]/system/role-auth`
- `GET http://[TARGET]/system/role`
- `GET http://[TARGET]/system/dict-data`
- `GET http://[TARGET]/system/dict`
- `GET http://[TARGET]/system/tag-data`
- `GET http://[TARGET]/system/tag`
- `GET http://[TARGET]/monitor/job-log`
- `GET http://[TARGET]/monitor/job`
- `GET http://[TARGET]/resReport/relateDevice`
- `GET http://[TARGET]/resReport/chart`
- `GET http://[TARGET]/vision/job/log`
- `GET http://[TARGET]/vision/job/index`
- `GET http://[TARGET]/system/menu/getRouters`
- `GET http://[TARGET]/system/menu/getRoutersByAppId`
- `GET http://[TARGET]/system/config/list`
- `GET http://[TARGET]/system/config`
- `GET http://[TARGET]/system/config/configKey`
- `GET http://[TARGET]/system/config/refreshCache`
- `GET http://[TARGET]/system/app/list`
- `GET http://[TARGET]/system/app`
- `GET http://[TARGET]/system/app/getAllApp`
- `GET http://[TARGET]/system/app/restartApp`
- `GET http://[TARGET]/file/file-minio/object/upload`
- `GET http://[TARGET]/file/file-minio/object/getImg`
- `GET http://[TARGET]/report/reportDashboard`
- `GET http://[TARGET]/report/dataSet/queryAllDataSet`
- `GET http://[TARGET]/report/dataSet/detailBysetId`
- `GET http://[TARGET]/report/reportDashboard/getData`
- `GET http://[TARGET]/report/reportDashboard/export`
- `GET http://[TARGET]/websocket`
- `GET http://[TARGET]/system/desktop/getInfo`
- `GET http://[TARGET]/system/desktop`
- `GET http://[TARGET]/system/desktop/getDeskTopRouters`
- `GET http://[TARGET]/system/desktopGroup/getAllDesktopGroups`
- `GET http://[TARGET]/system/desktopGroup/getDesktopGroupByName`
- `GET http://[TARGET]/auth/login`
- `GET http://[TARGET]/auth/external/login`
- `GET http://[TARGET]/auth/refresh`
- `GET http://[TARGET]/system/user/getInfo`
- `GET http://[TARGET]/auth/logout`
- `GET http://[TARGET]/system/app/getAppByAppId`
- `GET http://[TARGET]/system/externalSystem/getAllExternalSystem`
- `GET http://[TARGET]/system/user/sendCode/login`
- `GET http://[TARGET]/system/user/sendCode/reset`
- `GET http://[TARGET]/system/user/resetPwdByCode`
- `GET http://[TARGET]/auth/sms/login`
- `GET http://[TARGET]/login`
- `GET http://[TARGET]/reset`
- `GET http://[TARGET]/bind`
- `GET http://[TARGET]/register`
- `GET http://[TARGET]/workbench`
- `GET http://[TARGET]/changepwd`
- `GET http://[TARGET]/externalLogin`
- `GET http://[TARGET]/bridge`
- `GET http://[TARGET]/apply`
- `GET http://[TARGET]/audit`
- `GET http://[TARGET]/index`
- `GET http://[TARGET]/playmode`
- `GET http://[TARGET]/map`
- `GET http://[TARGET]/visonReport`
- `GET http://[TARGET]/gismap`
- `GET http://[TARGET]/contentOffice`
- `GET http://[TARGET]/user`
- `GET http://[TARGET]/flowable`
- `GET http://[TARGET]/apps`
- `GET http://[TARGET]/cabinet`
- `GET http://[TARGET]/video`
- `GET http://[TARGET]/area`
- `GET http://[TARGET]/server`
- `GET http://[TARGET]/unifiedMonitoring`
- `GET http://[TARGET]/lampstand`
- `GET http://[TARGET]/home`
- `GET http://[TARGET]/behaviorTaskReal`
- `GET http://[TARGET]/eventReport`
- `GET http://[TARGET]/operationLog`
- `GET http://[TARGET]/test`
- `GET http://[TARGET]/code`
- `GET http://[TARGET]/system/configuration/list`
- `GET http://[TARGET]/system/configuration/edit`
- `GET http://[TARGET]/system/api/user/register/dept`
- `GET http://[TARGET]/system/api/user/register/code`
- `GET http://[TARGET]/system/api/user/register`

## 漏洞详情
### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://[TARGET]/system/config/list
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://[TARGET]/system/config
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://[TARGET]/system/config/configKey
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://[TARGET]/system/config/refreshCache
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://[TARGET]/system/configuration/list
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://[TARGET]/system/configuration/edit
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://[TARGET]/system/api/user/register/dept
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://[TARGET]/system/api/user/register/code
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://[TARGET]/system/api/user/register
- **证据**: Status: 200

