# B4 第二轮：现有结构放不进 64KiB，停止再改

判定：维持 FAIL。这一轮不改实现、不重编 musl、不重跑作者全套。`31c2d40eb17822b6f2d5992cb414a403fdba5d21` 保持为上一件制品。`approvedSwitch` 仍是 false。

## 为什么现有结构过线

全局上限仍是 65536 字节，并且必须计入可归因的在途记录、保留记录、导出、gate、控制缓冲和 goroutine 栈。当前代码把一块正好 65536 的 arena 用满，栈和套接字缓冲在这块之外。

源码：

- `src/state.go` 的 `maxBytes = 64 * 1024`。`fixedBudget()` 是索引 256 + 导出帧 864 + gate 缓冲 4096 + 10×80 记录。`maxInflight()` 为 744。两者相加由 `init` 检查等于 65536。
- `src/budget.go` 的 `armBudget` 执行 `make([]byte, maxBytes)`，这 65536 字节一直可达。
- 同文件把 `controlHeapLimit = 128 * 1024` 写在 arena 外面。这就是被退回的口径，本轮不保留为合规预算。
- `src/control_linux.go` 在 `listen` 里 `go acceptLoop`，`acceptLoop` 再为每个连接 `go func` 启动处理，信号量上限 2。这些栈由 Go `runtime.stackalloc` 分配，不能放进 `[]byte`。工具链 `runtime/stack.go` 里 `stackMin = 2048`，`startingStackSize` 初始为 `fixedStack`。

实测（只跑了下限探针，CGO_ENABLED=0，未改预算）：

| 点 | goroutine | StackInuse / StackSys |
|---|---|---|
| `start` 前 | 2 | 425984 |
| 监听 goroutine 起来后 | 3 | 458752（+32768） |
| 两个 root 处理端阻塞在读时 | 5 | 仍是 458752 |

监听这一条额外栈已经是 32768 字节，并且在两个处理端同时活着时没有退回。它和 65536 的 arena 同时存在：65536+32768=98304，大于 65536。

同一探针里，控制连接的 `SO_RCVBUF` 和 `SO_SNDBUF` 都是 212992。单是接收缓冲就已经大于 65536。这是内核套接字缓冲，不是 Go 堆；即便只把 Go 栈算进上限，现有结构也已经超过。

## 不实施的原因

把 arena 缩小、少留在途槽，或取消控制 goroutine，都是另一套结构。本轮命令禁止在现有结构放不下时继续改，也禁止第三次修复。没有新的 musl 制品，没有把旧的 249ns、242ns、9510ns、11485ns 四批样本改名或回填。

## 给调度的短计划

保持 FAIL 和 draft。若还要这条诊断，下一件独立决定只能是其中一件，而不是再让作者改同一预算：

1. 明确 64KiB 不包含 Go 栈和内核套接字缓冲，并写出新的上限文本。这与本轮命令相反，作者不能自行采用。
2. 放弃进程内 Unix 监听。没有这条 goroutine 和套接字，当前这条控制面就不存在。
3. 停止本候选。`c2e43bf7…` 与 `a8ca1a47…` 都只是 `approvedSwitch=false` 的旧制品，不是启用制品。

作者没有做这三件里的任何一件。
