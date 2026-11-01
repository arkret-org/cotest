# 用户资料修改

## 目标

验证账户所有者从 Inkson `Settings / Account` 真实修改显示名称、简介并上传、发布和清除头像。浏览器产生明确的 `ak.profile.create|update`，Coland viewer 投影必须与 UI 一致；刷新后不得恢复已清除的头像。

## Spec 锚点

- `models/profile.md`：ActorProfile 的 `avatar_blob_ref` 与 create/update 语义。
- `crypto-media/media-and-blob.md`：头像 blob 的上传与引用。
- `interfaces/http-api.md`：`POST /_arkret/self/account/profile` 与 viewer surface。

## 流程与断言

1. 通过真实注册、邮箱验证、OAuth、身份创建和恢复密钥确认建立浏览器自己的账号与设备，进入账户设置；不依赖测试专用 WASM 会话注入。
2. 从 UI 填写非空显示名称与简介并保存，断言 Inkson 发布 `ak.profile.create` 或 `ak.profile.update`；viewer 返回相同 `display_name` 与 `profile_fields.biography`。
3. 选择有效 PNG，在裁剪对话框确认上传。
4. 断言 blob 上传后发布的是同一 profile 的 `ak.profile.update`，且返回成功。
5. 保留头像并冷刷新，观测浏览器真实认证的 `/_arkret/self/account/viewer`，断言显示名称、简介与 canonical content-addressed `avatar_blob_ref`；要求图片完成像素解码且无 Blob 错误。
6. 从 UI 清除头像，断言再次发布 `ak.profile.update`；冷刷新后真实 viewer 中头像为空。
7. 刷新页面，清除状态仍保持。

## Evidence 边界

业务写操作和身份密钥全部由正常 UI 建立。服务端投影来自浏览器实际认证的 viewer GET 响应，冷刷新后的可见图像是独立渲染断言；不读取密钥或自行续期不透明 grant。
