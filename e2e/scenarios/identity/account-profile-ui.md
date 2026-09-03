# 用户资料头像修改

## 目标

验证账户所有者从 Inkson `Settings / Account` 真实上传、发布并清除头像。浏览器产生 blob 上传和 `ak.profile.create|update`，Soland viewer 投影必须与 UI 一致；刷新后不得恢复已清除的头像。

## Spec 锚点

- `models/profile.md`：ActorProfile 的 `avatar_blob_ref` 与 create/update 语义。
- `crypto-media/media-and-blob.md`：头像 blob 的上传与引用。
- `interfaces/http-api.md`：`POST /_arkret/self/account/profile` 与 viewer surface。

## 流程与断言

1. 以真实 Coauth DPoP grant 打开 Inkson，进入账户设置。
2. 选择有效 PNG，在裁剪对话框确认上传。
3. 断言 blob 上传后，Inkson 向 canonical profile endpoint 发布 `ak.profile.create` 或 `ak.profile.update`，且返回成功。
4. 轮询 `/_arkret/self/account/viewer`，断言 canonical `avatar_blob_ref` 为 content-addressed blob。
5. 从 UI 清除头像，断言发布 `ak.profile.update`，viewer 中头像为空。
6. 刷新页面，清除状态仍保持。

## Evidence 边界

业务写操作全部由 Inkson 产生；测试仅用 DPoP viewer GET 作为独立投影 oracle。身份建立仍使用 session injection，因此不声明注册/登录 UI 覆盖。
