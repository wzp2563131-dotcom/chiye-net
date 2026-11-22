# B1–B4 author fix evidence

This is an author rerun. It is not an independent isolation PASS and it does not close section 6 of the review.

Source identity `6a8e0e935cdaa52b6aa21a63cf705d41743806fc` still has the same `patch/reality_server_dial_hook.diff`. `approvedSwitch` remains false. Previous evidence files were not rewritten. The old musl SHA `c2e43bf718c0b4fd9503d3adc62f4ddc45aec5bf6af83c2b512326ac8cc10e59` is only the earlier false build.

## What changed

- B1: entry sample stays before gate/reservation. A second ctx/deadline/time sample is taken immediately before `inner`, and the return sample is taken immediately after `inner` returns. Gate-wait expiry and inner-wait expiry are different enum triples.
- B2: a definitive gate failure on EXPORT calls the same permanent stop. A non-definitive busy result does not. A refused export does not consume the one-shot. A later healthy gate does not enable recording. STOP still answers.
- B3: SO_PEERCRED allows only uid 0. The directory and socket stay owned by the service euid, mode 0700/0600. The service is not raised to root.
- B4: reserving the byte that makes the accounted total exactly 65536 latches a permanent size stop. The heap is one 65536-byte arena. Fixed layout is 256 + 864 + 4096 + 800 = 6016. The other 59520 bytes are 744 slots of 80. Control listener overhead is a separate ceiling of 128KiB, not part of the 64KiB arena.

## Author commands

Raw logs: `evidence/fix-b1b4/raw-logs/`. Each command has meta, stdout, stderr, and exit code. Go 1.26.10, `GOTOOLCHAIN=local`, `CGO_ENABLED=1`.

| Directory | argv | Exit |
|---|---|---|
| `gofmt` | `gofmt -l .` | 0 |
| `govet` | `go vet ./...` | 0 |
| `gotest-race` | `go test -race -count=1 -timeout 300s .` | 0 |
| `gotest-json` | `go test -count=1 -timeout 240s -json .` | 0, 23 pass |
| `intree-race` | `go test -race -count=1 -timeout 300s -mod=readonly ./common/diag10443` | 0 |

New tests in that JSON run: `TestExpiryDuringGateDiffersFromInner`, `TestExportGateFailureLatchesAndBusyDoesNot`, `TestExactCapPermanentStopAndHeap`, `TestRootOnlyPeerSocket`.

The three earlier performance figures are unchanged and are not this run: original batch max 249ns, single-test rerun max 242ns, gotest-json batch max 9510ns. None is a production ≤1ms proof.

## Musl candidate

Same recipe as the previous false build: cronet-go `0d28acc44093df24b2526dea3d6ffefd6b0a54f0`, `build-naive --target=linux/amd64 --libc=musl`, tags from `release/DEFAULT_BUILD_TAGS` plus `with_musl`, `read_tag` version `1.14.4`, `CGO_ENABLED=1`, `-trimpath`, `-s -w -buildid=`. Built twice.

| | |
|---|---|
| New SHA256 | `a8ca1a476fc55b437fcce8c0b2576296fc2144f7a2fd0a00a192f7aa7d0f3d16` |
| Bytes | 92094272 |
| file | ELF x86-64, statically linked, stripped |
| ldd | `not a dynamic executable` |
| buildinfo | go1.26.10, CGO_ENABLED=1, same tags, vcs `c005f35300ce76427dc285481ec5695f5b179cd2`, `vcs.modified=true`, module `v1.14.4+dirty` |

Dirty is the diagnostic patch. This is not production `fe23d7000aaaa91f40b63641a65a1a84d96b5f179c65b63f34893e238884cd5c`.

Binary copy: `/opt/cursor/artifacts/10443-fix-b1b4/sing-box-musl`.

## Still unproven

Not an independent PASS. Not a production ≤1ms bound. The 19:11 config file is not the in-memory config. No backup and no switch. Findings stay open. `approvedSwitch=false`, so this binary is not an enabled artifact.
