# Federation outbound signing and trust_domain

验证 soland 出站 federation push 必须绑定 RFC 9421-style HTTP Message Signature、RFC 9530 `Content-Digest`、双端 service DID、双端 `trust_domain` 与幂等键。

## 范围

- 出站 `POST /_arkret/peer/peer/events` 带 `Idempotency-Key`、`Content-Digest`、`Signature-Input`、`Signature`。
- 签名 transcript 覆盖 `@method`、`@target-uri`、body digest、source/destination service DID、source/destination trust_domain、canonical request hash。
- body digest 篡改、缺失 trust_domain、trust_domain mismatch 都会使接收端验签失败。
- 同 peer + idempotency key 重放不产生第二条 outbox row。
- service key rotation/revoke 后，旧 signed request 不再能用新 service public key 验过。
- 入站 `peer events submit` 对 tampered `Signature` 返回 4xx，并在错误信息里给出 key rotation refresh hint（由 `federation/cross-server` live case 覆盖）。

## 不验证

- 入站 federation handler 的完整错误 envelope 字段矩阵；当前 live case 断言 4xx 与 key rotation hint，详细矩阵留给 API conformance。
- UI 层跨服务器邀请完整往返；该流程继续由 `federation/cross-server` 覆盖。

## Live 用例

1. 正向: outbound POST 生成完整 spec headers,并可用 source service public key 验签。
2. 负向: body digest 被篡改后签名 transcript 失效。
3. 负向: 缺失 destination trust_domain 后验签失败。
4. 负向: destination trust_domain mismatch 后验签失败。
5. 重放: 同 peer + idempotency key 命中幂等,不写重复 outbox row。
6. 撤销: service key rotation 后旧请求验签失败。
