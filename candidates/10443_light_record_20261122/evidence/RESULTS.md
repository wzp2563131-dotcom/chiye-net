# 本次作者测试

19:11 只读批次补上了 argv 路径上的当前配置文件身份，见 `pins/pins.json`。那是当时的文件字节，不是进程内已加载配置。`tcp_fast_open` 与目标 `detour` 字段不存在，不能写成已认证的非 TFO。程序与测试没有因这批事实改接口。没有再读主机，没有备份，没有部署。

工具链：`go1.26.10 linux/amd64`，官方包 SHA256 `ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5`。`CGO_ENABLED=1`。`GOTOOLCHAIN=local`。

源码：`SagerNet/sing-box` `c005f35300ce76427dc285481ec5695f5b179cd2`，tree `53d42183c16f692689448fbb949c7162564e9462`。`go.mod` 无 `replace`。这只证明该提交的源码模块文件；不能证明被过滤的两条二进制模块行。

五个依赖的 zip `h1` 与 `go.sum` 一致，模块 Origin 提交为：

- utls `v1.8.7` = `f7d52c22f3a8d2f510ad1470f75cb6c3fe26aa37`
- sing `v0.9.7-0.20261023115459-5dc452e537bf` = `5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f`
- tfo-go `v2.3.2` = `8b60f807823b0e3c8e80fad1cfbb21fe120bac57`
- sing-quic = `7e0a5869a5f49ed0a685143345dfda0448bbc708`
- quic-go `v0.61.0-sing-box-mod.12` = `80c132feb2112b5d0d88d02f941b1e68e56a2722`

utls 模块 zip 内 `reality.go` 与该提交原文 SHA256 同为 `9258864cc512e05302f5eb7d6a95efd7ae64bafcb45cb3b725086368740ab393`，扁平化行仍在。

## 命令与计数

在 `candidates/10443_light_record_20261122/src`：

- `gofmt -l .` 无输出
- `go vet ./...` 通过
- `go test -race -count=1 -timeout 300s .`：19 通过，`ok 1.065s`
- `go test -count=1 -timeout 180s -json .`：19 通过

在打过补丁的临时 sing-box 模块：

- `CGO_ENABLED=1 go test -race -count=1 -timeout 300s -mod=readonly ./common/diag10443`：`ok 1.063s`

19 个测试名：`TestABOverhead`、`TestControlExportOnceStopAndGate`、`TestStopDuringExportAndBusy`、`TestGateFailureLeavesStopAndDoesNotConsumeExport`、`TestSocketLifetimeAndRefusal`、`TestPeerPredicate`、`TestSchemaRejectsMutation`、`TestConcurrentDialsStayInsideCaps`、`TestApprovedSwitchIsOff`、`TestSchemaTypesHaveNoStrings`、`TestDisabledPathDoesNotRecordOrAllocate`、`TestSuccessDiscardAndNonTarget`、`TestExpiredCancelAndUnknownContext`、`TestTypedClassBeforeFlatten`、`TestTFOAndNonTFOBranches`、`TestBudgetsDoNotRenew`、`TestSizeBudgetFailsClosed`、`TestGateParserBoundaries`、`TestNonWhitelistErrnoIsUnknown`。

## 可重复的诊断测试二进制

```text
go test -c -trimpath -buildvcs=false -ldflags=-buildid= 
```

两次 SHA256 都是 `09c3e6504e375cfd95305bbef253bea421dd3519f8c6687fc60fafbc89448f6a`。这是诊断包测试二进制，不是 sing-box，更不是现场 `fe23d700…`。

## common/tls 全 tag 编译

`go test -c -tags <现场 tag 全集> ./common/tls/` 链出 `tls.test`，SHA256 `52a358120f0d374f0f283c44a81c54bcbe7d582cad5d3fdab1b3b7755502b065`。`go version -m` 显示 go1.26.10、`CGO_ENABLED=1` 与全部现场 tag。`ldd` 指向 `libc.so.6` 与 glibc 动态链接器。本机没有 musl 工具链，`with_musl` 没有把链接切到 musl。没有链接 `cmd/sing-box`，避免用 glibc 冒充现场 musl 二进制。

## A/B

非 race，同一闭包，假拨号立即返回成功。预热 256，配对样本 4096。关路径与开路径交替。gate 使用夹具并冻结时钟，所以热路径不含 `/proc` 读。冷 gate 另计 32 次夹具读取。

增量纳秒：min 67，p50 154，p90 155，p99 172，max 249。关闭 p50 26 / p99 27；打开 p50 180 / p99 198 / max 275。两次 `AllocsPerRun` 都是 0。4096 次打开成功路径的 `Mallocs`、`TotalAlloc`、`NumGC` 增量都是 0。冷 gate max 41619 ns。

这些数字只属于这台 4 vCPU 云主机上的合成调用。race 检测器下同一次试验的增量 max 是 16567 ns，不能拿来当开销。`<=1ms` 仍不是生产验收结论。它也不是 10443 的历史原因。

原始样本：`ab-deltas.bin`（4096 个小端 int64，32768 字节）。摘要：`ab-summary.json`。主机当时 load1 0.29，PSI some avg10 19.34，MemAvailable 约 4831344 kB。
