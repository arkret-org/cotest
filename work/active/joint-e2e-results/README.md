# cotest joint-e2e 全量复核

当前没有尚未闭环的已确认问题类别。

RC-6 invite locator 生命周期已按 spec 修复并通过标准 `joint-full` 定向运行：
`artifacts/runs/20260719-084249/joint-e2e`。

待重新执行标准全量命令：

```powershell
.\scripts\run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall
```

若全量运行发现新失败，将按 spec 重新聚类记录；若所有可执行用例通过且只保留有明确 profile 原因的 expected skip，则删除本文件。
