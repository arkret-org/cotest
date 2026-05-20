# Incident response workflow

## 目标

覆盖真实 SRE 事故处理流程:值班人创建 war room,后端同学诊断并回复,对外沟通同学发布脱敏进展,最后值班人沉淀最终摘要和 postmortem。该场景把消息 reply/edit、priority notification、状态 FSM、文档 Morph 串成一条业务链路,避免只测单页 smoke。

## Actors

| Actor | 角色 |
|---|---|
| oncall | incident commander,创建空间、确认告警、编辑最终摘要 |
| backend | owner,诊断根因、发布 mitigation |
| comms | 对外沟通,只发布脱敏状态更新 |

## Main flow

1. oncall 创建 `SEV-2 checkout` space,seed backend + comms。
2. oncall 发布初始 alert,并 reply ACK。
3. backend reply 根因诊断。
4. comms reply 对外更新,断言对外更新不泄漏内部根因细节。
5. backend 发布 mitigation。
6. oncall 编辑初始 alert,把 root cause 和 mitigation 合并到最终摘要。

## Edge cases

- **E-incident.status**:状态 FSM 不允许 `investigating -> resolved` 跳过 `mitigated`;合法转移写 audit。
- **E-incident.priority**:`SEV-1` priority 绕过 on-call 的 DnD,但 observer 的普通 DnD 仍生效。
- **E-incident.postmortem**:postmortem Document Morph 与 incident space 建结构化 relation,并保留版本列表。

## Implementation notes

- 当前主流程先保留 `test.fixme`:已有 timeline 能表达大部分步骤,但 seed-member invite 投射、priority notification、incident-specific status field 尚未稳定。
- status FSM 需要 yougen 暴露 `incident-status-*` testid,soland 暴露对应 `incident.status.transition` audit。
- priority notification 依赖 discovery/push-notifications 的 DnD override 策略。
- postmortem 依赖 documents/collaboration 的 Document Morph 与版本投影。
