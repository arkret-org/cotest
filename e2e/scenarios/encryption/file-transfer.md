# Actor-private 文件传输

## 目标

验证 Inkson `/files` 的真实上传链：明文文件只在客户端出现，Soland Blob Service 收到并返回 ciphertext，文件名与记录通过加密 account data 保存；刷新后客户端可恢复并显示文件名。

## Spec 锚点

- `models/file-transfer.md`：actor-private scope、`file_transfer` purpose、加密 record 与 retention。
- `crypto-media/media-and-blob.md`：ciphertext blob、content-addressing 与认证下载。
- `models/private-objects.md`：principal-private account data 边界。

## 流程与断言

1. 用户进入 Inkson `/files`，选择一个带唯一明文内容和文件名的文本文件。
2. 断言 blob upload 请求不含明文文件名/内容，返回 canonical `ak:blob:sha256:...`。
3. 断言 account-data write 携带 encrypted-value schema，wire 不含明文文件名/内容。
4. 断言 UI 显示解密后的文件名、media type 和 Available 状态。
5. 以 `purpose=file_transfer` 认证下载 blob，断言为 octet-stream 且 bytes 不等于明文。
6. 刷新 UI，文件记录仍可解密恢复。

## Evidence 边界

上传和 account-data 写入由 Inkson 产生；测试的 DPoP blob GET 只验证存储边界。身份建立使用 session injection，不声明注册/登录 UI 覆盖。
