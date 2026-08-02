# Protocol journey coverage（PJ01–PJ18）

这份地图跟踪跨服务、跨状态的协议旅程，而不是单个 endpoint 是否存在。机器真源是
[`tests/fixtures/protocol-journey-coverage.json`](../tests/fixtures/protocol-journey-coverage.json)，
`tests/protocol_journey_coverage.rs` 会校验 18 条旅程齐全、状态 fail-closed、证据文件与
marker 真实存在。

当前复核基线：`arkret-spec@916994898c2da05fd32ec71dbf379b19f0ec278b`。

这里使用 `PJ01`–`PJ18`；`agent-journeys/scenarios/*.json` 中的 `J01` 等编号仅是单个
场景内 checkpoint，二者不共享命名空间。

状态定义：

- `existing`：关键阶段已有确定性协议断言，可以分布在少量互补测试中。
- `partial`：有真实组件覆盖，但至少一个关键连接点缺失、协议冲突或仅条件运行。
- `missing`：尚无公开接口测试证明完整纵向旅程；相邻组件覆盖不算旅程完成。

| ID | 流程 | 状态 | 主测试层 | 当前关键缺口 |
|---|---|---|---|---|
| PJ01 | 用户注册与首设备可用 | partial | Playwright joint-e2e | bootstrap credential 未注册；enroll 响应丢失不可安全重试 |
| PJ02 | 登录与会话生命周期 | existing | Playwright joint-e2e | — |
| PJ03 | 多设备授权、同步、撤销与恢复 | partial | Playwright joint-e2e | fresh-device restricted credential 缺 machine schema |
| PJ04 | 联系建立与私聊资格 | partial | Playwright joint-e2e | signed Event 与跨 PS consent carrier 缺失 |
| PJ05 | 同域成员稳定私聊首条密文 | partial | Rust black-box | 规范已统一 stable binding；Cotest 尚未串联首条密文 |
| PJ06 | 跨域成员稳定私聊与重试 | partial | Playwright joint-e2e | 条件运行；coordinator handoff 无接口 |
| PJ07 | 已有稳定私聊恢复 | missing | Rust black-box | 规范已明确复用坐标；Cotest 无 offline/KP 空/restart/block/rejoin 恢复测试 |
| PJ08 | Realm founding unit 与 MLS genesis | existing | Rust black-box | — |
| PJ09 | 多准入模式成员加入与 MLS 自愈 | partial | Rust black-box | 旧 atomic fixture；ordinary join 无 KP reservation |
| PJ10 | leave/remove/ban、MLS Remove 与 rejoin | partial | Rust black-box | rejoin 的历史和新 Welcome 未闭环 |
| PJ11 | 加密历史可见性与旧 epoch 密钥 | partial | Playwright joint-e2e | T0/removed 规则冲突；recovery-key 撤权重验仍有 fixme |
| PJ12 | 加密消息生命周期与重放 | partial | Rust black-box | edit/reaction/redact 未统一使用真实 MLS envelope |
| PJ13 | 撤销后的密钥安全边界 | partial | Rust black-box | 多个安全面仍是分散断言 |
| PJ14 | 联邦同步、补历史、分区恢复与去重 | existing | Rust black-box | — |
| PJ15 | 离线延迟写与在线重验 | partial | Rust black-box | 在线 helper 仍默认申请 lease；纵向重验缺失 |
| PJ16 | 个人 Agent provision→pair→join→密文 | partial | Rust black-box | 规范已统一单 Event/三轴；主测试仍是 closed Event pair + 旧 runtime_state |
| PJ17 | Agent Sidecar 边界与幂等 | partial | Rust black-box | signed material、pending removal 与 approval 真源缺失 |
| PJ18 | Account lifecycle/recovery 级联 | partial | Rust black-box | 级联未联测；claimed KP 终态不明 |

确定性协议与密码学状态优先 Rust black-box；浏览器客户端、多服务协调和真实 UI 状态
使用 Playwright joint-e2e。Agent Journeys 只做补充 UX 探索，不代替 stable id、密文、
授权、epoch、重试和撤销等确定性断言。

静态 drift guard 当前钉住三个不能被误报为绿色的已知问题：

- PJ09：`membership_and_mls_commit_are_atomic` 旧 fixture；
- PJ15：通用在线 Event helper 默认申请 `AuthorizationLease`；
- PJ16：Agent provision 仍构造 accountability/selector closed Event pair。

这些 guard 不替协议选择冲突分支；对应旅程只能保持 `partial`/`missing`，直到测试迁移
完成，或其余规范真源真正收敛。
