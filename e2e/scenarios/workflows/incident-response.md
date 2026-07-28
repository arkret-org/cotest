# Incident response workflow

## 目标

覆盖真实 SRE 事故处理流程:值班人创建 war room,后端同学诊断并回复,对外沟通同学发布脱敏进展,最后值班人沉淀最终摘要和 postmortem。该场景把消息 reply/edit、public-update hygiene、状态 FSM、文档 Morph 串成一条业务链路,避免只测单页 smoke。

## Actors

| Actor   | 角色                                                  |
| ------- | ----------------------------------------------------- |
| oncall  | incident commander,创建 Realm、确认告警、编辑最终摘要 |
| backend | owner,诊断根因、发布 mitigation                       |
| comms   | 对外沟通,只发布脱敏状态更新                           |

## Main strand

1. oncall 创建 `SEV-2 checkout` Realm,seed backend + comms。
2. oncall 发布初始 alert,并 reply ACK。
3. backend reply 根因诊断。
4. comms reply 对外更新,断言对外更新不泄漏内部根因细节。
5. backend 发布 mitigation。
6. oncall 编辑初始 alert,把 root cause 和 mitigation 合并到最终摘要。

## Edge cases

- **E-incident.status**:状态 FSM 不允许 `investigating -> resolved` 跳过 `mitigated`;合法转移写 audit。
- **E-incident.priority**:`SEV-1` 公开更新在 E2EE Realm 中可发送且服务端不泄露明文;public-update guard 会阻止包含内部根因/token 等敏感细节的更新。
- **E-incident.postmortem**:postmortem 文档 surface 与 incident Realm 建结构化 relation payload,并保留版本列表。

## Implementation notes

- 主流程已是 live `test()`:覆盖三位 actor 的 war room、诊断、脱敏更新、mitigation 与最终摘要编辑。seed-member invite 投射和完整 push notification routing 由各自的专项 scenario 继续覆盖。
- status FSM 已由 inkson `incident-status-*` 控件和 soland `incident.status.transition` audit 覆盖。
- sanitized public-update guard 与 E2EE no-plaintext-leak 检查已 live;完整 DnD override 属于 push notification 策略覆盖。
- postmortem link controls 与本地版本列表已 live;完整 Document Morph 投影仍归 P2 文档链路。
