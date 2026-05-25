# 通话(1:1 + group + mute + screen-share + recording policy)

## 目标

WebRTC 信令 + media 层的端到端:alice 主动 1:1 call bob → mute / screen share → 挂断;然后 group call(alice+bob+carol)→ recording policy 校验。Call Morph 状态机:`ringing → connecting → active → ended`;ephemeral 信令通过 Sync Service 路由,**不进** durable event history(除了 Call Morph 本身);ICE config 含 pairwise pseudonym TURN credentials。

不验证:WebRTC 媒体协议本身(假设 Playwright + Chrome 能跑 fake media)、加密(E2EE 通话留到后续 scenario)。

## Spec 锚点

- `crypto-media/webrtc-signaling.md` §2 — 设计:ephemeral 信令 + media vs trust path
- `crypto-media/webrtc-signaling.md` §3 — Call modes(`p2p` / `sfu` / `mcu`)
- `crypto-media/webrtc-signaling.md` §4 — Call Morph(state、recording_policy)
- `crypto-media/webrtc-signaling.md` §5 — Permissions(`call.start`、`call.join`、`call.screen_share`、`call.record`、`call.moderate`、`call.end_for_all`)
- `crypto-media/webrtc-signaling.md` §6-§6.3 — ICE Server Discovery(pairwise pseudonym + credential refresh)
- `crypto-media/webrtc-signaling.md` §7 — Signaling envelope(`cx.call.signal`)
- `crypto-media/webrtc-signaling.md` §8 — 1:1 信令 payload(offer/answer/candidate/hangup)

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
2. yougen 客户端:
   - 创建 Call Morph:`{ morph_type: "call", mode: "p2p", state: "ringing", participants: [alice.did, bob.did], recording_policy: "none" }`
   - 提交 `cx.morph.create`
   - 调 `POST /api/v1/calls/ice-config?call_id=<callId>&device_id=<alice_dev>` 拿 ICE config:`{ stun_servers, turn_servers: [{ url, username: "pairwise-pseudonym", credential, expires_at }] }`(spec §6)
3. alice 客户端用浏览器 RTCPeerConnection 创建 offer SDP
4. yougen 发 `cx.call.signal`(ephemeral)`{ kind: "invite", offer_sdp, call_id, target: bob.did }`
5. soland Sync Service 路由该 signal 到 bob 的 to-device 队列
6. bob yougen 收到 → UI 弹 "Incoming call from alice"(`incoming-call-toast` testid)
7. bob 点 "Accept",创建 RTCPeerConnection 应答
8. yougen 发 `cx.call.signal { kind: "answer", answer_sdp }`
9. ICE candidates 多次 `cx.call.signal { kind: "candidate", candidate }` 双向交换
10. 媒体 channel 建立;Call Morph 状态 `ringing → connecting → active`
11. 断言:alice/bob 两端的 UI 都进入 in-call 视图,`call-status-active` testid 可见,duration timer 开始

### Phase B — Mute + screen share

12. alice 点 "Mute mic":本地 track.enabled = false
13. yougen 发 `cx.call.signal { kind: "mute_state", muted: true }`(ephemeral)
14. 断言:bob 视图 alice 头像旁显示 muted icon
15. alice 点 "Share screen":
    - 调 `getDisplayMedia()` 拿 screen track
    - addTrack 到 peer connection,renegotiate SDP
    - 发 `cx.call.signal { kind: "media_state", screen_share: true }`
16. 断言:bob 视图显示 alice 的 screen
17. (Call Morph 的 `recording_policy = "none"` 应阻止后续 recording 尝试,见 Phase D)

### Phase C — Hangup

18. alice 点 "Hang up"
19. yougen 发 `cx.call.signal { kind: "hangup" }`
20. 客户端 close peer connections,Call Morph 提交 `cx.morph.update { state: "ended", ended_at }`
21. 断言:Call Morph state = ended,call duration 持久化

### Phase D — Group call(SFU + recording policy)

22. alice 在 space `S_team` 中点 "Start group call"
23. Call Morph:`{ mode: "sfu", state: "ringing", participants: [], recording_policy: "allow" }`
24. bob、carol 收到 invite signal,先后加入(`cx.call.signal { kind: "focus_join" }`)
25. SFU 媒体路径建立;三人都能听到看到对方
26. carol 点 "Start recording"
27. yougen 客户端:
    - 校验 carol 是否持 `call.record` capability(spec §5)
    - 调 `POST /api/v1/calls/<callId>/recording/start`
28. soland 校验 `recording_policy = "allow"` + carol 的 capability → 接受
29. 后端把 recording metadata 写入 Call Morph:`recording_started_by: carol.did`,`recording_blob_ref: <blob_id>`
30. 断言:alice/bob/carol UI 三方都显示"🔴 Recording in progress"(`recording-indicator` testid)

### Phase E — Recording policy 拒绝

31. 另起一个 group call,这次 Call Morph 设 `recording_policy: "none"`
32. carol 点 "Start recording"
33. yougen 应在本地禁用按钮(预防性);若 bypass,soland 反应 `failed_precondition`、`reason_code = "recording_policy_violation"`
34. 断言:UI 报错 "Recording not permitted in this call"

### Phase F — Mid-call ICE credential refresh

35. 假设 TURN credential 5 分钟过期;长 call 触发 refresh
36. yougen 调 `POST /api/v1/calls/<callId>/ice-config/refresh` → 拿新 credential
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

- **soland 已落地(P3-070)**:`/api/v1/webrtc/sessions` 对参与者开放 signal append/read,并在 create/post/get 响应中派生 `ringing → connecting → active → ended` call_state;peer routing 由参与者读取同一 session 的信号覆盖。
- **soland 已落地(P3-071)**:`/api/v1/calls/ice-config` 与 refresh 端点签发 realm/call-scoped STUN/TURN 配置,TURN username 使用 pairwise pseudonym,mid-call refresh 轮换 credential;`mode=sfu` 与 `recording_policy=allow|none` 已持久化并强制录制策略。
- **yougen 已落地(P3-070)**:`/call` 的本地 renderer FSM 暴露 `call-status-ringing`、`call-status-connecting`、`call-status-active`、`call-status-ended`,与 soland 状态词汇一致。
- **remaining yougen UI 缺口**:mute/screen-share/hangup 的真实 signal emit、recording indicator、group/SFU roster 由 GAP-P3-072 覆盖。
- **测试侧难点**:
  - Playwright 用 `--use-fake-ui-for-media-stream` + `--use-fake-device-for-media-stream` 让 getUserMedia 返回 fake track 避免硬件依赖
  - getDisplayMedia 在 headless 难;screen-share 可能要 stub
  - WebRTC peer connection 在两个 Playwright contexts 间需要让 Sync 真的把 signal 转发;现有 harness 应该 OK

## 总耗时预估

约 3-4 分钟(WebRTC handshake + 媒体协商 + recording 上传)。
