---
name: e2e tests must model real multi-user/multi-server scenarios, not thin UI smoke
description: Cotest's joint e2e shouldn't be a per-page testid checklist — it should run end-to-end business flows with multiple users (sometimes across multiple servers) communicating through the protocol. Design the scenarios first, then write tests.
type: feedback
---

The joint e2e suite must exercise typical end-to-end business flows: multiple users, communicating through one or more servers, completing real protocol operations. Per-page testid sanity checks ("the chat panel renders") are not the bar.

**Why:** 2026-05-15 the user said: "现在的 e2e 测试实际内容很少, 太过简单. 实际上你应该拉起多个典型的应用场景, 还得模拟多用户之间通过同一个/多个不同的服务器完成各种通讯. 你要先设计这些业务流程, 然后再根据具体的流程写测试." Cotest is the joint integration harness; if its tests don't model federation, multi-actor coordination, and protocol-level flows, the suite gives false confidence.

**How to apply:**
- When adding or rewriting e2e tests, start from a business scenario document: who the actors are, what server(s) they live on, what protocol operations they perform, what state must converge.
- Scenarios should cover at minimum: multi-user same-server interaction, cross-server federation, invite/accept across servers, sync after offline edits, permission/moderation boundaries, recovery/device verification.
- Resist the urge to add a "smoke test for view X" without an end-to-end flow behind it — that pattern produced the brittle /product-page suite that broke when the demo playground was removed.
- Design scenarios before opening test files; confirm with the user before writing.
