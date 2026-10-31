# User Access local-ahead candidate / 用户访问本地超前候选

**Date / 日期：** 2026-10-31  
**Scope / 范围：** LIMITED local-ahead candidate only / 仅限本地超前候选

This directory records a **LOCAL ahead candidate versus historical evidence**. It contains only the two files that differ from (or are absent in) the D3 evidence snapshot. It is not the full `user_access_candidate` tree.

本目录记录**相对历史证据的本地超前候选**。只收录相对 D3 证据快照超前或独有的两个文件，不是完整的 `user_access_candidate` 树。

## Status / 状态

| Item / 项 | Status / 状态 |
|-----------|----------------|
| Nature / 性质 | LOCAL ahead vs historical evidence / 本地超前，对照历史证据 |
| Finding | **OPEN / 仍开放** |
| 05 / 06 | **NOT issued / 未签发**（no Gate PASS / 无 Gate PASS） |
| Candidate enforcer | **UNVERIFIED_AHEAD / 超前未核验** |
| Production / 生产 | **NOT production / 非生产** |
| Source of Truth / 事实来源 | **NOT SoT / 非 SoT** |
| Deploy / 部署 | **NOT authorized / 未授权**（no real VPS / 无真机 VPS） |

## Explicit non-claims / 明确不声称

- The Finding stays **OPEN**. This directory does **not** close the Finding. / Finding **仍开放**。本目录**不**关闭 Finding。
- Do **not** read this candidate as Gate PASS, 05 PASS, or 06 PASS. / **不得**将本候选读成 Gate PASS、05 通过或 06 通过。
- This is **not** production and **not** a Source of Truth. / **非**生产，**非**事实来源（SoT）。
- This does **not** authorize deploy or a real VPS. / **不**授权部署，也**不**授权真机 VPS。
- Local tests, if any, do **not** replace 05/06 and do **not** close the Finding. / 本地测试（若有）**不能**代替 05/06，也**不能**用来关闭 Finding。

## Files / 文件

Relative to this directory / 相对本目录：

| Path / 路径 | Bytes / 字节 | SHA-256 | vs evidence / 相对证据 |
|-------------|--------------|---------|------------------------|
| `src/chiye_net/user_access/enforcer.py` | 57409 | `8067cd0aeaaf511136b23e53680926e2ccbcb856016d5897a6b11bf684b5a862` | AHEAD（evidence / 证据 `54d6401e120229a156b1e270397c2843afe198b58fe88cc16a4ce98d66c1a738` / 57008） |
| `tests/test_result_state_binding.py` | 4191 | `88c0c024f1ddf4ee2d76c0a795a4eb3db86c3355cd01603b8709c36eabc73bd1` | NEW（absent from evidence tree / 证据树无此文件） |

Source bundle SHA-256 / 来源压缩包 SHA-256：`2dc4c7f75dcb585b8042cc45204257dde54de269147388d5b4dd3f7cbddb8380`

Same-hash files already present in the D3 evidence snapshot are **not** included. / 与 D3 证据快照同哈希的文件**未**纳入。
