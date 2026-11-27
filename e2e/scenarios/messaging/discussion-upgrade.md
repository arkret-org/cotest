# Realm 内的讨论消息

两个成员在同一个 Strand 的 discussion Track 发送消息。客户端从同一条 Realm 提交流读取两条消息并核对其路由。更新 Realm 已读披露策略后，成员读取签名快照，验证整份策略、来源及版本，并在 Station 重启后再次核对。

原 Playwright 场景已迁至 `tests/api_mls_migrations.rs::realm_discussion_api_migration`。
