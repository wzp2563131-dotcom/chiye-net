#!/bin/sh
# Acquire the pinned sing-box commit in a temp directory, verify sums, apply
# the diagnostic patch, and test it. Does not deploy, restart, or commit the
# upstream tree. Does not drop build tags to force a sing-box link.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
WORK=${WORK:-/tmp/chiye-10443-build}
PIN_COMMIT=c005f35300ce76427dc285481ec5695f5b179cd2
PIN_TREE=53d42183c16f692689448fbb949c7162564e9462
GO_SHA=ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5
TAGS="with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_naive_outbound,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0,with_musl"

mkdir -p "$WORK"
if [ ! -x "$WORK/go/bin/go" ]; then
  curl -fsSL --retry 3 -o "$WORK/go1.26.10.linux-amd64.tar.gz" https://go.dev/dl/go1.26.10.linux-amd64.tar.gz
  echo "$GO_SHA  $WORK/go1.26.10.linux-amd64.tar.gz" | sha256sum -c -
  tar -C "$WORK" -xzf "$WORK/go1.26.10.linux-amd64.tar.gz"
fi
export PATH="$WORK/go/bin:$PATH"
export GOTOOLCHAIN=local
export CGO_ENABLED=1
export GOMODCACHE="$WORK/modcache"
export GOCACHE="$WORK/gocache"
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
export GOSUMDB="${GOSUMDB:-sum.golang.org}"

go version | grep -q 'go1.26.10 '

if [ ! -d "$WORK/src/.git" ]; then
  mkdir -p "$WORK/src"
  git -C "$WORK/src" init -q
  git -C "$WORK/src" remote add origin https://github.com/SagerNet/sing-box.git
  git -C "$WORK/src" fetch --depth 1 origin "$PIN_COMMIT"
  git -C "$WORK/src" checkout --detach FETCH_HEAD
fi
test "$(git -C "$WORK/src" rev-parse HEAD)" = "$PIN_COMMIT"
test "$(git -C "$WORK/src" rev-parse 'HEAD^{tree}')" = "$PIN_TREE"
if grep -q '^replace' "$WORK/src/go.mod"; then
  echo "source go.mod contains replace; stop" >&2
  exit 1
fi

git -C "$WORK/src" checkout -- common/tls/reality_server.go
rm -rf "$WORK/src/common/diag10443"
mkdir -p "$WORK/src/common/diag10443"
cp "$ROOT/src/"*.go "$WORK/src/common/diag10443/"
rm -f "$WORK/src/common/diag10443/go.mod"
patch -p1 -d "$WORK/src" < "$ROOT/patch/reality_server_dial_hook.diff"

cd "$ROOT/src"
gofmt -l .
go vet ./...
go test -race -count=1 -timeout 300s .
go test -count=1 -timeout 180s .

cd "$WORK/src"
go test -race -count=1 -timeout 300s -mod=readonly ./common/diag10443

cd "$ROOT/src"
go test -c -trimpath -buildvcs=false -ldflags='-buildid=' -o "$WORK/diag-a.test" .
go test -c -trimpath -buildvcs=false -ldflags='-buildid=' -o "$WORK/diag-b.test" .
sha256sum "$WORK/diag-a.test" "$WORK/diag-b.test"
cmp "$WORK/diag-a.test" "$WORK/diag-b.test"

# Typecheck the hook inside real common/tls with the reported tag set.
# This is not cmd/sing-box and not a musl link.
cd "$WORK/src"
go test -c -o "$WORK/tls.test" -tags "$TAGS" ./common/tls/
go version -m "$WORK/tls.test" | head -n 20
ldd "$WORK/tls.test" | head -n 20
echo "tls.test is a package test binary. It does not reproduce the production sing-box digest."

if ! command -v musl-gcc >/dev/null 2>&1 && ! command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then
  echo "GAP: musl toolchain absent. Not linking cmd/sing-box. Tags kept: $TAGS" >&2
  echo "A glibc link would not be the reported musl binary and is not attempted." >&2
  exit 0
fi
echo "musl compiler exists; full link is still not authorized by this harness" >&2
exit 0
