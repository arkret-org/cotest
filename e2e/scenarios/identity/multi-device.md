# 多设备授权与撤销

首设备由 root-signed PCR genesis descriptor 授权并由自身私钥证明持有。后续设备只能由当前 generation 中已 accepted、未撤销的设备批准：批准设备签 `ak.device.authorize` Event proof，新设备签同一 payload 的 possession proof，`authorization_binding_kind` 固定为 `accepted_device`。

测试必须覆盖：目标设备 PoP 篡改拒绝、批准设备不是 current/active 时拒绝、同一 payload exact replay、撤销后设备写入与 KeyPackage claim 被拒、re-anchor 后旧 generation 被 fence。任何路径都不得读取 DID 中的业务委派。
