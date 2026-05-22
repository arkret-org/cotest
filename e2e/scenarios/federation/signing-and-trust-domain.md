# Federation outbound signing and trust_domain

验证 soland 出站 federation push 必须绑定 RFC 9421-style HTTP Message Signature、RFC 9530 `Content-Digest`、双端 service DID、双端 `trust_domain` 与幂等键。

## 范围

- 出站 `POST /api/v1/federation/push-operations` 带 `Idempotency-Key`、`Content-Digest`、`Signature-Input`、`Signature`。
- 签名 transcript 覆盖 `@method`、`@target-uri`、body digest、source/destination service DID、source/destination trust_domain、canonical request hash。
- body digest 篡改、缺失 trust_domain、trust_domain mismatch 都会使接收端验签失败。
- 同 peer + idempotency key 重放不产生第二条 outbox row。
- service key rotation/revoke 后，旧 signed request 不再能用新 service public key 验过。

## 不验证

- 入站 federation handler 的完整 401/403 错误 body 字段。当前 scenario 用 soland integration test 直接验证接收端必须执行的签名判断规则，避免在入站 verifier 尚未独立拆出时继续保留 fixme。
- UI 层跨服务器邀请完整往返；该流程继续由 `federation/cross-server` 覆盖。

## Live 用例

1. 正向: outbound POST 生成完整 spec headers,并可用 source service public key 验签。
2. 负向: body digest 被篡改后签名 transcript 失效。
3. 负向: 缺失 destination trust_domain 后验签失败。
4. 负向: destination trust_domain mismatch 后验签失败。
5. 重放: 同 peer + idempotency key 命中幂等,不写重复 outbox row。
6. 撤销: service key rotation 后旧请求验签失败。
