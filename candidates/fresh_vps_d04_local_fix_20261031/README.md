# D-04 local hash-pin fix candidate / D-04 本地哈希钉修复候选

**Date / 日期：** 2026-10-31  
**Scope / 范围：** LIMITED local candidate only / 仅限本地候选

This directory records **LOCAL candidate repairs after the hash-pin fix**. It contains only the three changed files from the local fix bundle. It is not the full `fresh_vps_candidate` tree.

本目录记录**哈希钉修复后的本地候选修补**。只收录修复包中的三个改动文件，不是完整的 `fresh_vps_candidate` 树。

## Status / 状态

| Item / 项 | Status / 状态 |
|-----------|----------------|
| Offline suite / 离线套件 | **86/86** (local unittest only / 仅本地 unittest) |
| D-03 | **OPEN** |
| D-04 | **OPEN** |
| Gate B | **NOT authorized / 未授权** |
| Production / 生产 | **NOT production / 非生产** |
| Source of Truth / 事实来源 | **NOT SoT / 非 SoT** |

## Explicit non-claims / 明确不声称

- Do **not** read this candidate as Gate PASS. / **不得**将本候选读成 Gate PASS。
- Findings stay open. This does **not** close D-03 or D-04. / Finding 保持开放。本目录**不**关闭 D-03 或 D-04。
- This does **not** authorize deploy, a real VPS, or Ansible execution. / **不**授权部署、真机 VPS 或 Ansible 实执行。

## Files / 文件

Relative to this directory / 相对本目录：

| Path / 路径 | Bytes / 字节 | SHA-256 |
|-------------|--------------|---------|
| `ansible/controlled_entry.py` | 12803 | `08e7f2758ce1f394ff34e4ff34e0ac9fdbde217d6e0cc04c8031a199cb70c2be` |
| `tests/test_bootstrap.py` | 29746 | `25f4e4f62dba2895196e721362eef72ac139c6db4901670e36dbdaf069b4d7fd` |
| `evidence/d04-repair/builder-receipt.json` | 5731 | `a91b5cb9785d346ffe9ae3736e19381c1e3c6ac7bc9ee1cb00572b27e5c71a63` |

Source bundle SHA-256 / 来源压缩包 SHA-256：`95873e15ca643cf4343cacea3cdc3e5db8191f17101647adde0691f6b529806c`
