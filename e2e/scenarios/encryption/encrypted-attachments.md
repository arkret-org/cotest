# E2EE 加密附件（0805）

## 正式合同

真相源为 `crypto-media/media-and-blob.md` §§2–3.3、§5、`models/content-types.md` 的 E2EE long-text，以及 `blob.schema.json`。上传 classification 为 closed `{scheme}`；transport MIME 为 `application/octet-stream`，服务端保存密文尺寸。明文 filename/MIME/尺寸、salt、nonce prefix 和完整 SDK descriptor 留在私有 ContentBlock。

每个新 object 在派生前耐久冻结独立 32-byte salt、authoring scope、immutable Genesis 和 exact winning checkpoint。内容密钥使用正式 MLS exporter Context，不使用当前 epoch fallback 或任意缓存 secret。`group_state_ref` 接受 EventId 或该 accepted Genesis/winning Commit Event 的 SHA-256 内容摘要等价引用；原始引用继续参与 AAD。拥有 ref、salt 或密文不授予历史读取权。

生产支持 `ak.blob.stream_aead.v1` + `mls_exporter_aead_xchacha20poly1305_stream`。whole-file/AES 继续失败关闭。每段 tag 与整个所选 Blob digest 全部通过后，才创建可用预览或下载结果。

## 运行拓扑与执行入口

一台 runner-owned TLS Coland、独立 PostgreSQL/对象目录、一台真实 Coauth；发送者和接收者使用独立浏览器 context/Device。第三位 since-join 成员用于历史拒绝与真实 Add epoch 前进。

主用例：`tests/joint/encrypted-attachment-two-device.spec.ts`。补充服务分类、tus/restart 与 plaintext 回归：`tests/joint/blob-storage-classification.spec.ts`。唯一实现 owner 为 `arkret-work/tasks/impl-done/2026-09-30-0805-blob-upload-encryption-classification.md`（完成后归档路径以工作索引为准）。

通过 `scripts/run-joint-e2e.ps1 -StartCoauth` 运行，保留源码/lock/features 与 SUT build identity，不使用 HTTP 诊断环境替代 TLS 验收。

## 非空业务断言

1. 加密 composer 的“添加附件”菜单通过实际 file chooser 选择首个文件（Inkson #39），后续文件保留 File drop 路径；经 SDK KDF/AEAD、canonical multipart 和结构化私有 Message，由另一设备解密并显示实际 PNG pixels/bytes。只打开菜单不算上传通过。
2. 服务接受上传后丢失响应，发送端刷新恢复：salt、descriptor、nonce prefix、密文字节和 BlobRef 精确重用。
3. 草稿改走再改回取消旧 continuation；未完成附件不能发送，显式重试沿用原对象。
4. 同样输入的另一新 object 使用 fresh salt/key 和不同密文；跨多段大文件下载的 SHA-256 等于真实输入。
5. 超 inline 上限的加密 long-text 经 mandatory stream descriptor 发送；UTF-8 分页首尾和完整下载等于源正文。
6. 真正新增成员推进 epoch 后，旧授权成员刷新仍能读旧附件；since-join 成员按原 Message ID 读取返回404且没有历史预览。
7. 离开目标后原预览Blob URL不可用；密文 HTTP 响应被篡改后不产生原附件的可用 URL/preview；ciphertext presign 被拒绝。
8. 通过 runner 的真实 Station 只读数据库 lease 检查 `blobs`：只有 closed classification、octet-stream、密文尺寸；filename 为 null，无完整私有 descriptor。

## 证据边界

SDK 向量、native storage/codec 单测、TypeScript 检查分别证明各自边界，不能代替上述实际生产成功链。浏览器附件输入使用 File/Blob slice；Dioxus 的 `byte_stream()` 在当前版本整读 File，因此不用于浏览器生产路径。原生使用文件分段读取和受保护按需 KV。接收端先验证完整承诺，再输出 browser Blob URL 或原生可撤销临时文件能力。

运行状态、失败、自然退出和最终 pins 写入 0805 的本批报告；历史 P2-044 的测试及旧 helper 名称不作为现实现交付证据。
2026-10-14 最新冻结实际通过：真实provisioning 7/7，业务3项＋build-ID 4/4，自然exit0，0失败/跳过，secret scan通过。源码/lock/features/产物身份与原失败记录见 `arkret-work/reports/2026-10-14-0805-attachment-production-closeout.md`；三scope本地授权cut前提测试不冒充独立部署验收，whole-file/AES未启用。
