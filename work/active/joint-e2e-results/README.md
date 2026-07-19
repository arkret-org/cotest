# cotest joint-e2e 全量复核

## 当前基线

- 命令：`./scripts/run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall`
- 完整运行：`artifacts/runs/20260719-210052/joint-e2e`
- 480 tests：291 passed，22 failed，107 expected/profile skipped，60 因 serial 前置失败未运行。
- 测试阶段耗时 25.9 分钟，runner 总耗时 1588.1 秒；托管服务失败数为 0。
- JUnit 记录 15 个直接失败；Playwright 汇总中的另外 7 个是 serial suite 前置失败后的派生失败/未完成项，不能重复作为独立根因计数。

## 后续待聚类信号

本轮其余 JUnit 直接失败信号包括：

- account-data / UI projection：personal blocklist、consent、support escalation；
- session/sync：terminal auth polling 计数、offline queue 状态；
- Realm/Kanban：跨成员加密投影、列拖放/邀请状态；
- messaging：reaction/reply/mention routing 投影；
- invite/workflow：admin invite 状态、多个 workflow 的 invite/join、offline 或 redaction 前置项；
- workflow 的其余失败需在上游 serial 前置项解锁后重新确认，不能基于当前派生失败过早归因。

这些信号尚未假定为同一根因；继续逐类分析、复核并移除。
