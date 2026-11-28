# Realm link graph：关系可见，状态不传播

## 目标

验证 current-v1 的 Realm link 只是治理、发现、迁移与导航关系，不是 authority 或 policy carrier。建立
`governed_by`、`discoverable_from` 或其它标准 link 后，目标 Realm 仍必须用自己的本地 Event 表达 membership、
capability、policy、retention 与 notification 状态。

## Spec 锚点

- `arkret-spec/spec/v1/zh/models/realm-links.md` §2 — link graph 不承载跨 Realm 状态继承；
- 同文 §3 — 标准 link kind closed set；
- 同文 §5 — membership、capability、policy、retention、notification 等不得隐式级联；
- 同文 §6 — 每个目标 Realm 必须由本 Realm controller／issuer 分别签发本地 Event；
- [当时的 0046 裁决](https://github.com/arkret-org/arkret-work/blob/e663133fc3fca3167887f46ef54b24dba9f3432b/decisions/0046-realm-inheritance-clean-break-and-co-governed-join-gate.md)。

## 当前覆盖

静态用例校验父 Realm 成员门槛所要求的共同治理和当前成员记录，并验证调用方可提交的证明种类。见 [Realm link 合同测试](../../../tests/realm_link_clean_break.rs)。

原生场景创建两个 Realm，验证显式 link 可读、源 Realm 的权限不能授权目标写入，以及目标本地成员和授权生效后的写入。场景还比较 link 状态变更前后的业务记录，并检查服务重启后读取的状态。见 [原生测试入口](../../../tests/realm_links_live.rs) 和 [场景实现](../../../src/scenarios/realm_links_live.rs)。
