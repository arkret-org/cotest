# 实现任务的完成标准与测试追踪

`config/implementation-acceptance.json` 是工程追踪清单，正式协议仍以 `arkret-spec/spec/v1` 为准。它为每个 active owner 记录剩余验收摘要、正式来源、生产入口、可定位测试及仍缺场景。`contract`、`live`、`product` 表示入口责任，不表示该用例在当前源码已运行或已通过；`engineering` 表示生成、架构或覆盖清单检查。诊断、预期失败及 opt-in 用例不能升级为完整支持证据。

任务完成必须同时证明：

1. 正式适用合同与实际 producer／admission／read／delivery consumer 一致；合法前置真的抵达目标判定点。
2. 正例产生期望业务状态；错身份／scope／current／签名／CAS、撤权与隐私反例按注册结果拒绝，相关接受事务无部分写入。
3. 并发、exact replay、响应丢失、取消、crash／restart 保留原材料与原结果，迟到结果不能写入新会话；适用容量预算在真实路径测量。
4. 该 owner 的实际具名集合在同一冻结源码、lock、features、配置与 SUT 组合中非空执行、自然成功、无失败／跳过／预期失败，结果来源可核。最终跨仓联合组合仍由既有 0900 承接。

生成/KAT等价、纵向清理和Linux安全打包应在所属仓完成。Cotest只承接能跨真实客户端／服务观察的行为；为未挂载provider或缺生产consumer写一个固定成功fixture没有验收价值。

核对追踪清单（不构建、不执行业务）：

```powershell
python scripts/check_operation_test_coverage.py --check-acceptance
python -m unittest scripts.tests.test_operation_test_coverage.AcceptanceTraceabilityTests
```

这一模式显式需要 sibling `arkret-work`，普通 operation inventory 和 Cotest 构建不新增协调仓依赖。沿原扫描器定位真实 Rust／Playwright test 符号；它会拒绝漏owner、重复owner、验收数量或正文改变未同步、删除测试、helper冒充测试和静态完整claim。修改任务验收时须逐项审阅后同步 digest，不能用自动刷新掩盖 scope 裁剪。

2026-10-12新增两个 `to_device_offline_ordering` 真实HTTP场景，对应 device-lifecycle §7／1638 DR-C6：过期 exact replay、跨HTTP key及ACK后重放保留原结果；过期未ACK原envelope保留；过期或超过24h目标让混合batch整体param_invalid且零新入队。它们补队列合同覆盖，不能证明四种RecoveryMethod或恢复后编辑全部通过。

逐项处理及运行证据见[库存复核报告](../../arkret-work/reports/2026-10-12-impl-active-acceptance-audit.md)。未接线的大范围产品场景继续由相应 owner 实施，清单检查本身不关闭任务、不提高 profile／SDK claim。
