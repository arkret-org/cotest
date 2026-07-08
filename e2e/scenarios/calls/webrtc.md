# 通话(1:1 + group + mute + screen-share + recording policy)

## 目标

WebRTC 信令 + media 层的端到端:alice 主动 1:1 call bob → mute / screen share → 挂断;然后 group call(alice+bob+carol)→ recording policy 校验。Call Morph 状态机:`ringing → connecting → active → ended`;ephemeral 信令通过 Sync Service 路由,**不进** durable event history(除了 Call Morph 本身);ICE config 含 pairwise pseudonym TURN credentials。

不验证:WebRTC 媒体协议本身(假设 Playwright + Chrome 能跑 fake media)、加密(E2EE 通话留到后续 scenario)。

## Spec 锚点

- `crypto-media/webrtc-signaling.md` §2 — 设计:ephemeral 信令 + media vs trust path
- `crypto-media/call-state.md` §2 — Call modes(`p2p` / `sfu` / `mcu`)
- `crypto-media/call-state.md` §3 — Call Morph(state、recording_policy)
- `crypto-media/webrtc-signaling.md` §3 — Permissions(canonical `ck.call.*`:`ck.call.join`、`ck.call.signal.send`、`ck.call.screen_share`、`ck.call.record`、`ck.call.moderate` 等)
- `crypto-media/webrtc-signaling.md` §4-§4.1 — ICE Server Discovery(pairwise pseudonym + credential refresh)
- `crypto-media/webrtc-signaling.md` §5 — Signaling envelope(`ck.call.signal`)
- `crypto-media/webrtc-signaling.md` §6 — 1:1 信令 payload(offer/answer/candidate/hangup)

## 拓扑

- 1 × soland(含 media service endpoint + ICE config endpoint)+ 1 × coauth
- (sub-test)外置 TURN server(可 mock 或 coturn 容器)

## Actors

| 名字 | 角色 |
|---|---|
| alice | call initiator |
| bob | 1:1 callee + group participant |
| carol | group participant + recording attempter |

## Steps

### Phase A — 1:1 call alice → bob

1. alice 进 bob 的 contact / DM 视图,点 "Call"
2. inkson 客户端:
   - 创建 Call Morph:`{ morph_type: "call", mode: "p2p", state: "ringing", participants: [alice.did, bob.did], recording_policy: "none" }`
   - 提交 `ck.morph.create`
   - 调 `POST /_cokret/self/rtc/ice-config?call_id=<callId>&device_id=<alice_dev>` 拿 ICE config:`{ stun_servers, turn_servers: [{ url, username: "pairwise-pseudonym", credential, expires_at }] }`(spec §6)
3. alice 客户端用浏览器 RTCPeerConnection 创建 offer SDP
4. inkson 发 `ck.call.signal`(ephemeral)`{ kind: "invite", offer_sdp, call_id, target: bob.did }`
5. soland Sync Service 路由该 signal 到 bob 的 to-device 队列
6. bob inkson 收到 → UI 弹 "Incoming call from alice"(`incoming-call-toast` testid)
7. bob 点 "Accept",创建 RTCPeerConnection 应答
8. inkson 发 `ck.call.signal { kind: "answer", answer_sdp }`
9. ICE candidates 多次 `ck.call.signal { kind: "candidate", candidate }` 双向交换
10. 媒体 channel 建立;Call Morph 状态 `ringing → connecting → active`
11. 断言:alice/bob 两端的 UI 都进入 in-call 视图,`call-status-active` testid 可见,duration timer 开始

### Phase B — Mute + screen share

12. alice 点 "Mute mic":本地 track.enabled = false
13. inkson 发 `ck.call.signal { kind: "mute_state", muted: true }`(ephemeral)
14. 断言:bob 视图 alice 头像旁显示 muted icon
15. alice 点 "Share screen":
    - 调 `getDisplayMedia()` 拿 screen track
    - addTrack 到 peer connection,renegotiate SDP
    - 发 `ck.call.signal { kind: "media_state", screen_share: true }`
16. 断言:bob 视图显示 alice 的 screen
17. (Call Morph 的 `recording_policy = "none"` 应阻止后续 recording 尝试,见 Phase D)

### Phase C — Hangup

18. alice 点 "Hang up"
19. inkson 发 `ck.call.signal { kind: "hangup" }`
20. 客户端 close peer connections,Call Morph 提交 `ck.morph.update { state: "ended", ended_at }`
21. 断言:Call Morph state = ended,call duration 持久化

### Phase D — Group call(SFU + recording policy)

22. alice 在 Realm `R_team` 中点 "Start group call"
23. Call Morph:`{ mode: "sfu", state: "ringing", participants: [], recording_policy: "allow" }`
24. bob、carol 收到 invite signal,先后加入(`ck.call.signal { kind: "focus_join" }`)
25. SFU 媒体路径建立;三人都能听到看到对方
26. carol 点 "Start recording"
27. inkson 客户端:
    - 校验 carol 是否持 `call.record` capability(spec §5)
    - 提交 `ck.call.recording.start`,随后用 `ck.call.state` 推进
      `recording_state`
28. soland 校验 `recording_policy = "allow"` + carol 的 capability → 接受
29. 后端把 recording metadata 写入 Call Morph:`recording_started_by: carol.did`,`recording_blob_ref: <blob_id>`
30. 断言:alice/bob/carol UI 三方都显示"🔴 Recording in progress"(`recording-indicator` testid)

### Phase E — Recording policy 拒绝

31. 另起一个 group call,这次 Call Morph 设 `recording_policy: "none"`
32. carol 点 "Start recording"
33. inkson 应在本地禁用按钮(预防性);若 bypass,soland 反应 `failed_precondition`、`reason_code = "recording_policy_violation"`
34. 断言:UI 报错 "Recording not permitted in this call"

### Phase F — Mid-call ICE credential refresh

35. 假设 TURN credential 5 分钟过期;长 call 触发 refresh
36. inkson 重新调 `POST /_cokret/self/rtc/ice-config`,携带同一
    `realm_id`/`call_id`/`device_id` → 拿新 credential
37. peer connection ICE restart
38. 断言:call 不掉线,媒体 channel 持续

## Observable assertions(合并)

- Phase A 步骤 11:1:1 call 建立
- Phase B 步骤 14/16:mute + screen share 状态广播
- Phase C 步骤 21:Call Morph ended
- Phase D 步骤 30:group call + recording allowed
- Phase E 步骤 34:recording policy 拒绝
- Phase F 步骤 38:ICE refresh 不掉线

## Edge cases / sub-tests

- **E18.1 callee 离线**:bob 不在线;`ringing` 超时(spec lifetime_ms 默认 30s)→ Call Morph 转 `missed`
- **E18.2 信令乱序**:candidate signal 比 offer 先到 → bob 客户端缓冲或拒绝
- **E18.3 carol 中途加入 1:1 call**:Phase A 进行中,carol 尝试 join → 应拒绝(p2p mode 不允许第三方);切换到 SFU 需要 alice 显式升级
- **E18.4 alice ban carol mid-call**:alice 在 group call 中 ban carol → MLS Remove(若 E2EE call)+ carol 被踢出 media path
- **E18.5 force_turn**:NAT 严格环境,客户端 force-TURN → 媒体经 TURN relay,断言 candidate type 全是 `relay`
- **E18.6 mute remote**:alice 持 `call.moderate`,强 mute carol → carol 媒体被服务端拒绝转发,carol UI 显示 "muted by moderator"
- **E18.7 pseudonym TURN credentials**:断言 turn_servers[].username 不暴露 alice.did 明文(应当是 pairwise pseudonym,spec §6)

## Implementation notes

- **spec wire**:通话信令走 `POST /_cokret/self/ephemeral` +
  `ck.call.signal`;持久状态走 `ck.call.state` / `ck.call.recording.start`;
  媒体凭证走 `/_cokret/self/rtc/ice-config` 与 `/_cokret/self/rtc/token`。
  soland-private WebRTC / calls surfaces 已退役,本场景不得依赖。
- **soland/cotest 覆盖**:服务端覆盖 ephemeral `ck.call.signal` 路由、TTL、
  capability guard、self-device filtering、ban 后 token 拒绝、LiveKit token
  claim;cotest 覆盖 `ck.call.signal` receiver vectors 与 `/_cokret/self/rtc/*`
  realtime policy guards。
- **inkson 预期**:`/call` 的本地 renderer FSM 暴露
  `call-status-ringing`、`call-status-connecting`、`call-status-active`、
  `call-status-ended`,并只通过 spec wire 发送
  `invite`/`answer`/`candidate`/`mute_state`/`media_state`/`hangup`。
- **测试侧难点**:
  - Playwright 用 `--use-fake-ui-for-media-stream` + `--use-fake-device-for-media-stream` 让 getUserMedia 返回 fake track 避免硬件依赖
  - getDisplayMedia 在 headless 难;screen-share 可能要 stub
  - WebRTC peer connection 在两个 Playwright contexts 间需要让 Sync 真的把 signal 转发;现有 harness 应该 OK

## 总耗时预估

约 3-4 分钟(WebRTC handshake + 媒体协商 + recording 上传)。
