# Evidence completion

Source identity remains `6a8e0e935cdaa52b6aa21a63cf705d41743806fc`. Hooks, `approvedSwitch`, and control-plane code were not edited. This directory is new evidence only.

## 1. ab-deltas.bin

Retrieved with `git cat-file blob ac5919aeea3150aa3397b471a21e58ae532b7529` from that commit.

| Check | Result |
|---|---|
| Git blob | `ac5919aeea3150aa3397b471a21e58ae532b7529` |
| Bytes | 32768 |
| SHA256 | `e8735c779f31c28ad451fe9878efecb515226f0845fc4c7ba54dffb4e9c2182f` |

`evidence/completion/ab-deltas.bin` matches that blob byte for byte. The copy already at `evidence/ab-deltas.bin` in `6a8e0e9` is the same bytes. No reconstruction.

Agent copy: `/opt/cursor/artifacts/10443-evidence-pack/ab-deltas.bin`.

## 2. Raw author logs

`6a8e0e9` had `evidence/RESULTS.md`, which is a summary, not raw logs. The same commands were re-run here against that source. Each directory under `raw-logs/` has `meta.txt` (argv, cwd, env), `stdout.txt`, `stderr.txt`, and `exit_code.txt`.

| Log | Command | Exit |
|---|---|---|
| `gofmt` | `gofmt -l .` | 0, empty stdout |
| `govet` | `go vet ./...` | 0, empty stdout |
| `gotest-race` | `go test -race -count=1 -timeout 300s .` | 0 |
| `gotest-json` | `go test -count=1 -timeout 180s -json .` | 0, 19 tests passed |
| `ab-overhead` | `go test -count=1 -timeout 180s -run ^TestABOverhead$ -v .` with `DIAG10443_AB_OUT` and `DIAG10443_AB_RAW` | 0 |
| `testbin-a`, `testbin-b` | `go test -c -trimpath -buildvcs=false -ldflags=-buildid=` | 0, both SHA256 `09c3e6504e375cfd95305bbef253bea421dd3519f8c6687fc60fafbc89448f6a` |
| `intree-race` | `go test -race -count=1 -timeout 300s -mod=readonly ./common/diag10443` after the existing patch | 0 |
| `tls-test-c-glibc` | `go test -c` of `./common/tls/` with the tag string below | 0 |

Env for those runs: `go1.26.10`, `GOTOOLCHAIN=local`, `CGO_ENABLED=1`, `GOOS=linux`, `GOARCH=amd64`, `GOAMD64=v1`.

`RESULTS.md` had paraphrased the tls command as “现场 tag 全集”. The command actually run, and re-run here, was:

`go test -c -o /tmp/chiye-10443-evidence/tls.test -tags with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_naive_outbound,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0,with_musl ./common/tls/`

That output is a glibc `common/tls` test binary, SHA256 `52a358120f0d374f0f283c44a81c54bcbe7d582cad5d3fdab1b3b7755502b065`. It is not `cmd/sing-box` and not the musl program.

The race command has no `-v`, so its raw stdout is one `ok` line. The JSON log is the full event stream.

## 3. Musl cmd/sing-box

Toolchain is the pinned cronet-go checkout `0d28acc44093df24b2526dea3d6ffefd6b0a54f0` from `.github/CRONET_GO_VERSION`, then `go run ./cmd/build-naive --target=linux/amd64 --libc=musl download-toolchain`. The first download stopped with `ModuleNotFoundError: No module named 'requests'`. `python3-requests` 2.31.0 was installed and the same download command completed. Clang is `llvmorg-23-init-10931-g20b6ec66-11`. The sysroot is OpenWrt 23.05.5 `gcc-12.3.0` musl for x86_64.

`git describe --tags` on the pinned commit, after fetching tag `v1.14.4` (it points at `c005f35300ce76427dc285481ec5695f5b179cd2`), and `go run ./cmd/internal/read_tag --ci --nightly` with `CGO_ENABLED=0`, wrote `version=1.14.4`. An earlier `read_tag` built with the musl `CC` failed to exec; that log is `musl-build-readtag-cgo-fail.log`.

Exact link of `./cmd/sing-box`, twice, with the existing diagnostic patch already applied:

`CGO_ENABLED=1 GOOS=linux GOARCH=amd64`

`CC` = cronet clang `--target=x86_64-openwrt-linux-musl` and the OpenWrt musl sysroot

`CGO_LDFLAGS=-fuse-ld=lld`

tags = `release/DEFAULT_BUILD_TAGS`, plus `with_musl`

ldflags = `-X github.com/sagernet/sing-box/constant.Version=1.14.4` plus `release/LDFLAGS` plus `-s -w -buildid=`

Both outputs SHA256 `c2e43bf718c0b4fd9503d3adc62f4ddc45aec5bf6af83c2b512326ac8cc10e59`, 92091776 bytes. `file` says statically linked, stripped. `ldd` says `not a dynamic executable`.

`go version -m` shows go1.26.10, `CGO_ENABLED=1`, those tags, `vcs.revision=c005f35300ce76427dc285481ec5695f5b179cd2`, `vcs.modified=true`, main module `v1.14.4+dirty`. Dirty is the diagnostic patch. This is not the host binary `fe23d7000aaaa91f40b63641a65a1a84d96b5f179c65b63f34893e238884cd5c`.

The 92MB binary is not in git. Agent copy: `/opt/cursor/artifacts/10443-evidence-pack/sing-box-musl`.

## Still unproven

No production `<=1ms` bound. No CI claim. No proof the process loaded the 19:11 file. No backup. No root-cause closure for 10443 or 8443. Omitted host build settings are not recovered. `approvedSwitch` is still false, and this stripped binary does not contain the contiguous socket-path bytes.
