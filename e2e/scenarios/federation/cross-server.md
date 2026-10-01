# 跨服务器联邦

验证独立 Station 的定向邀请、受邀者经自己 Station 加入、双向消息、committed replication、逐 stream 补拉与成员退出后的投递隔离。信任根为原签 producer Event、治理 Station 的 RealmCommit 与 RFC 9421 peer 请求签名。

## 当前合同

- 正式拓扑入口为 `scripts/run-joint-e2e.ps1 -ServerCount 2` 或更多 Station；各站使用独立身份、状态和 PostgreSQL。`-DnsSuffix localhost` 保留 TLS、service identity 与未注册主机负例，不写 hosts。
- `POST /_arkret/peer/events` 的 `committed_replication` 分支只携完整原 Event、source Commit，按数组顺序返回 stored/duplicate/rejected。
- peer 读取为 `POST /_arkret/peer/streams/scan`；self 读取为 `POST /_arkret/self/streams/scan`。指定唯一 stream、恰好一个方向位置参数、limit，发送 canonical JSON。
- 被邀请者从本站受保护的邀请通知取 locator hints，向本站 `self/realm-joins/prepare` 发起准备，再自签 `ak.invite.accept` 提交本站；本站向已验证 current governance Station 转发，不代签 producer Event。
- 普通 Realm 明确为 `since_join`。成员 Station 无 join 前复制权，不能把 all-history 不可证区间当作可读历史；读与复制均保持 failure closed。
- owner 在远端 join 前接受默认 discussion。成员加入提供读区间，Message 写权限由 owner 对远端完整 AccountId 明确签发；先等 join 可读，再回读该 exact grant Event/Commit，随后发送。

## 产品与协议断言

1. Alice 的浏览器创建 Realm、通过 admin 发出定向邀请，本地 pending 行和 Bob 本站邀请通知可见；通知不代表加入。
2. Bob 从本站准备并提交自己的 join，server1 返回其精确 covering Commit；成员完整 AccountId 在双方获准 current 中出现。
3. typed message prepare 核对完整 unsigned Event、request digest、producer Actor、scope、时间和 payload；exact prepare replay 相同，异 intent 同 request ID 为 duplicate_conflict。原签 Event 提交后 exact replay 返回原 Commit，零新 position。
4. Alice/Bob 双向消息都在对方本站获准 stream 可读；不要求 Bob 获得 join 前 Event。
5. server2 没有托管 joined 成员时，bootstrap 的合法原签 pairs 每项 rejected 且零持有；join 后 exact message pair 重放均 duplicate。
6. peer scan 恢复返回获准连续 source pairs；接收只 stored/duplicate，同一 Event 本地恰一次。
7. Bob 本人 leave 后，server1 继续接受 Alice 的消息，server2 不持有之后的 Commit；保留轮询与延迟复核。
8. unsigned peer scan、篡改 RFC 9421 请求签名均拒绝；认证失败不披露 key rotation hint。

## 大历史边界

`prepared authoring and join` 的大历史变体先接受并退出一个本地成员，再接受18条不同原签 Event 的相同 Schema definition。Schema subject 不可变，同一 `$id` 的内容保持逐字相同，current 只有一个定义；不能通过替换不同字节或扩大8MiB Snapshot预算实现。

owner 从自己的获准 Realm stream 以limit5逐页读取，断言每项 full Event 与Commit绑定、position连续、分页有界、18个 accepted Event ID恰一次，实际读回payload合计超过8MiB，且超过一页。`accepted-history-audit.json`仅记录subject数、accepted数、读回字节、页数和最终position。Bob之后通过标准join/bootstrap取得获准current，并完成双向typed Message；不能用合成大包、未提交history或API准备成功代替最终读取。

本场景的明文Realm用于验证网络authoring/admission/bootstrap；MLS加密、设备恢复、真实注册的产品分类与其它具名场景分开记录。API fixture与session injection不宣称为真实注册产品验收。

## 规范来源

- `sync/federation.md` §3、§3.2、§4.1.1、§5.3.1：source验证、复制权、opening join bootstrap与authority locator。
- `sync/authority-commit-log.md` §3–§4：exact Event/Commit、单stream连续position、duplicate与暂不可用。
- `sync/service-http-binding.md` §3.1：caller允许区间、readable floor、full/withheld与位置分页。
- `conformance/scalability-constraints.md` §4.1：Snapshot容量上限。
- `authority-commit-operations.schema.json#/$defs/peer_submit_request`与`stream_scan_request`。

## 历史记录

2026-09-12 的旧协议两次选择运行（`20260912-094216`、`20260912-100215`）均完成前置但在来源submit缺依赖失败。它们不证明current-v1加入、读取、消息或当前源码；完整历史上下文保留在Git，不再把退役carrier或旧harness配置作为实现合同。
