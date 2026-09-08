# Kanban 端到端（Board / List / Card / Drag / Archive / Comments）

## 目标与规范

在真实 Soland、Coauth、Inkson 上验证单用户看板流程。唯一规范来源是 `arkret-spec/spec/v1`：

- `zh/models/realm-and-space.md`：Space 层级、顶层 rank、Strand 位置 CAS 与生命周期。
- `zh/models/strand-and-message.md`：Strand、Discussion、私有内容和生命周期。
- `zh/models/relation.md`：结构关系的 Realm 约束。
- `zh/crypto-media/encryption-and-audit.md` 及注册的加密载体：MLS 状态验证与加密内容提交。

测试入口为 `e2e/tests/kanban/end-to-end.spec.ts`。多用户场景由 `project-simulation` 与 `cross-member-encrypted` 单独覆盖。

## 活跃测试链路

1. Alice 创建 Realm、Board Space 和三个 List Space。
2. 在 Todo 创建两个 Card Strand，归档 Card A 后恢复，验证主视图与归档视图的生命周期投影。
3. 构造已过时的跨列移动 basis，验证成功的移动与后续 `cas_conflict` 拒绝；不以旧的列表子项数组代替 Strand 位置 CAS。
4. 提交跨 Realm 的结构关系，验证 `cross_realm_structural_relation` 拒绝。
5. 对已归档 Strand 提交 Discussion 写入，验证 reducer 拒绝。
6. 等待所有 List 创建完成后，使用真实拖拽手柄把第三列移到第一列之前。创建尚未完成时，拖拽手柄不可用，提交路径不得把本地临时句柄当成 Space ID。
7. 验证列顺序的持久化：通过标准 `GET /_arkret/self/realms/{realm_id}/spaces` 读取同一 Board 下的 active List，按各 Space 顶层 rank 排序；刷新客户端后仍保持相同顺序。
8. 在新建 MLS 加密 Realm 的创建者设备上分别编辑 Description、Synthesis 和发送 Discussion 消息。验证实际提交被接受、私有文本不出现在明文 wire 中，并验证客户端解密渲染。

## 协议断言

- Event-derived 对象 ID 来自最终接受的 create Event；本地创建句柄不是协议 ID。
- Space 排序由 Space 顶层 `rank` 表达；测试不使用旧私有 `child_order` 读取接口。
- Strand 位置使用规范中的 CAS basis；`metadata.fields.status` 不能替代注册的 Strand stage/lifecycle 操作。
- 拒绝的结构关系、过时移动和归档写入不得产生目标共享状态修改。
- 加密写入必须取得已验证的 MLS transition 与可用密钥；不得为了测试通过降低内容加密要求、伪造 Welcome 或重建不相干的群组。
- HTTP Event 提交使用注册的 submission carrier，不发送裸 Event 兼容格式。

全量运行的实际通过、失败和串行未执行数量记录在对应 joint-e2e 运行产物中；本场景文档不替代运行证据。
