# 设计

## 问题

固定 utls `reality.go` 在 `DialContext` 返回后执行 `errors.New("REALITY: failed to dial dest: " + err.Error())`，类型丢失。相同超时文本也可以在真正 connect 之前由已到期 context 产生。本候选只在 sing-box REALITY 握手闭包里、这次包装之前取样。它不证明 connect、nginx 或 8443 的阶段。

## 挂钩

只改 `common/tls/reality_server.go` 的握手 `DialContext`。闭包仍把同一个 `ctx`、`network`、`addr` 交给原来的 `handshakeDialer.DialContext`，并原样返回 `conn` 与 `err`。

目标只认 `tcp`/`tcp4` 且地址字符串精确为 `127.0.0.1:10443`。utls 传入的是 `config.Type`（此处源码设为 `tcp`）和 `config.Dest`。不匹配就直接拨号，不读 gate，不分配记录。

## TFO 与非 TFO

19:11 的只读批次给出的是 argv `-C` 所指向路径上的当前文件字节，不是进程启动时的字节，也不是内存里已经生效的配置。入站 0 的 REALITY 目标写成精确的 `127.0.0.1:10443`。listener 的 `tcp_fast_open`、目标 dialer 的 `tcp_fast_open` 和目标 dialer 的 `detour` 都是字段不存在。字段不存在不是文件里的显式 false，也不是已经观察到的非 TFO。运行分支没有被认证。

固定源码里的条件机制，只在“内存中的选项等于缺省零值”时成立：`TCPFastOpen` 是 `bool`，`NewDefault` 写 `DisableTFO: !options.TCPFastOpen`。该树里没有把 `TCPFastOpen` 再赋成 true 的语句。因此若加载结果真是零值，`DisableTFO` 为 true，`DialSlowContext` 走非 TFO。这是条件，不是现场结论。listener 上的 `tcp_fast_open` 与握手目标 dialer 上的不是同一个字段。

源码里两条路径都从这一个闭包进去，钩子两条都盖住，不挑选一条当作生产事实：

- 选项为 false 时 `DisableTFO` 为 true，`DialSlowContext` 把原 ctx 交给 `net.Dialer`。
- 选项为 true 时用 `context.WithoutCancel`，`DialContext` 先返回慢打开连接，真正拨号在之后的 `Write`。
- `networkStrategy != nil` 时走并行接口拨号，仍在同一个 `DialContext` 里面。`detour` 字段不存在也不证明内存里没有 detour。

钩子不改这些选择。明确看不见的部分：TFO 路径在 `DialContext` 已返回 nil 之后才发生的 connect 错误。不为了看见它去挂钩 `Write`。

## 记录

只在错误返回时提交一条固定 64 字节记录。成功丢掉入场状态。字段只有枚举和整数：单调入口/调用前/返回偏移、进程内 8 字节记号、连接 ID 存在位与 `uint32`、两侧 `ctx.Err` 枚举、有无 deadline、有符号剩余纳秒、扁平化前的错误类。无 deadline 时剩余为 0，0 不是到期。

错误分类不调用 `Error()`。有界展开最多 4 步，只认 `context.Canceled`、`context.DeadlineExceeded`、白名单 `syscall.Errno`、`net.Error.Timeout`，以及 `*net.OpError` / `*os.SyscallError` 的内层。`Op == "dial"` 只变成枚举。未知保持未知，errno 记 0。分类 panic 被接住，不改变拨号返回值。

## 预算

全局一份，不是每连接一份：10 条错误，或逻辑占用 64KiB，或自记录臂启动起 30 分钟。先到者永久关闭，不自动续期，不取消真实拨号。

64KiB 记账含固定索引 256、导出预留 1024、以及在途和已提交记录各 64 字节。放不下就丢弃并关闭，不覆盖旧记录。30 分钟在下一次预约或返回时执行，没有后台计时器；已经在途的拨号返回后也不再提交。

## 负载 gate

没有新守护，也没有周期轮询。记录路径和导出路径在缓存超过 1 秒时，由当前调用者读一次 `/proc/loadavg`、`/proc/pressure/cpu`、`/proc/meminfo`，各有上限。`load1 >= 0.75`、CPU PSI `some avg10 >= 20`、或 `MemAvailable < 128MiB`，以及读/解析失败，都永久停止记录。

另一个调用者正在读且没有新鲜缓存时，这一条跳过，不据此永久关闭。缓存命中的“通过”最多旧 1 秒。这不是连续保护，也不能在没有拨号或导出时发现越阈。

STOP 不看 gate。导出时 gate 失败返回状态并不消耗那一次导出。

## 控制面

唯一路径：

- 目录 `/run/chiye-net`，必须是 0700，属主等于进程 euid
- 套接字 `/run/chiye-net/10443-diag.sock`，0600

没有令牌，没有 HTTP、pprof、公网端口、Clash API、443 或 8443。导出不写磁盘。应答就是这条连接上的一帧，载荷不超过 64KiB。

帧：请求 `C4D1` + 命令（1 STOP，2 EXPORT）；应答 `C4D0` + 状态 + 大端长度 + 载荷。没有别的命令。

目录用 `O_NOFOLLOW|O_DIRECTORY` 打开。套接字经 `/proc/self/fd/<dirfd>/10443-diag.sock` 绑定，避免解析父目录符号链接。已有同名项不删除、不覆盖。关闭时只在目录项仍是当初那个套接字 inode 时 `unlinkat`。监听 fd 的 sockfs inode 与目录项 inode 不是同一个，身份以不跟随符号链接的目录项为准。

`SO_PEERCRED` 只接受 uid 0 或进程 euid。权限主体是目录属主，也就是将来的 sing-box 服务账号；本候选不 `chown`。

监听失败则记录保持关闭。此时套接字上的 STOP 不存在。这是失败关闭，不是再开一条控制通道。

崩溃后留下的套接字会使下次绑定失败。候选不自动删除它。操作步骤只写在部署计划里，不是新命令。

## 文件

| 路径 | 作用 |
|---|---|
| `src/*.go` | 诊断包与测试。标准库。复制到 sing-box `common/diag10443`，不带 `go.mod` |
| `patch/reality_server_dial_hook.diff` | 唯一上游钩子 |
| `harness/acquire_build_test.sh` | 临时目录取固定源、校验、打补丁、测试 |
| `pins/pins.json` | 已核与仅报告的版本 |
| `evidence/` | 本次命令结果与 A/B 原始样本 |

上游整树不进入本仓库。
