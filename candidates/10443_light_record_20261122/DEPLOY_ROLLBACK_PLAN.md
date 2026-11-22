# 部署与回滚计划

本文件只是计划。现在不能执行。没有备份。独立复核与调度令都未发出。`approvedSwitch` 仍是 false。19:11 的身份不能代替短窗开始前的新校验。

## 已取得的身份，以及仍缺的部分

本环境没有重读主机。下列都是已批准只读批次的结果。

19:11 二进制 `/usr/bin/sing-box` SHA256 仍是 `fe23d7000aaaa91f40b63641a65a1a84d96b5f179c65b63f34893e238884cd5c`。unit `/usr/lib/systemd/system/sing-box.service` SHA256 `259fa4ee0a29fb863bd1597eba9392bd9767c679c1e28b8b1ee91ce1ea01c84d`。unit 正文未取。`DropInPaths` 这一属性存在且为空，只说明这个属性。`EnvironmentFiles` 属性缺失，仍是未知。能力与 xattr 未取。没有做备份。

argv 角色：`-C=/etc/sing-box`，该目录一层 `*.json` 只有 `/etc/sing-box/config.json`。19:11 当前文件 SHA256 `29b338a13c531af47abdc5c0d98c78845671f6c4dd85f00303d8d703c36c7935`，1404 字节，0640，root:gid988。`-D=/var/lib/sing-box`，0755，uid988/gid988，内容没有枚举。这是 argv 所指向路径上的当前字节，不是进程启动时的字节，也不是内存中已加载配置的证明。文件正文未进入本仓库。目录里只有一个 json，不能推出文件内部不再引用其他路径。

该当前文件里，入站 0 的 REALITY 目标是精确的 `127.0.0.1:10443`。listener 与目标 dialer 的 `tcp_fast_open` 字段都不存在，目标 dialer 的 `detour` 也不存在。缺字段不是显式 false，也没有认证运行分支。数据目录属主 uid988 不是已经证明的进程 euid。

共享的 sing-box 进程同时承载 443 与 8443。即使钩子只看 10443，换二进制或短重启也会打断这两路。

## 以后若另令获准

1. 短窗开始前重新核对二进制、unit、`/etc/sing-box/config.json` 的 dev/inode/size/属主/权限/SHA，并确认没有并发维护者。19:11 的哈希只是当时的身份。同时处理仍然未知的 `EnvironmentFiles`，以及未枚举的 `-D` 内容；能力与 xattr 也要在当时读取。进程 euid 以当时的进程为准，不用数据目录属主代替。
2. 在主机私有目录（计划为 `/root/chiye-net-diag-backup/<window-id>/`，0700，文件 0600）保存原二进制、unit 与当时实际文件的原字节。含密文件不进仓库、不进聊天。复制后核对备份 SHA，再核对来源身份未变。现在还没有这份备份。
3. 候选二进制单独命名，不覆盖唯一原件。配置字节保持不动。
4. `/run/chiye-net` 必须是 0700，属主等于当时的进程 euid，套接字 0600。不要为了让 root 连上而把服务提成 root。控制面只接受对端 uid 0。切换前单独核对：进程 euid、capability、user namespace、mount namespace，以及 root 在该命名空间里能否访问这个目录。本批没有给出进程 euid。不要预先创建套接字。若残留套接字，只在 `stat` 确认它是套接字后再由操作者删除；候选没有清理命令。
5. 只有调度令明确改 `approvedSwitch` 并重建之后，记录才会臂启动。STOP 与一次导出不需要再做服务动作。
6. 回滚用预先批准的 sing-box 服务短窗恢复原二进制字节、路径和权限，并重算 SHA。配置应保持原样。不重启整机，不 reload nginx，不改超时或路由。

记录器关闭失败时，先不要换回二进制来“停记录”。恢复原程序是另一项服务动作。
