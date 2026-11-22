#!/bin/bash
set -euo pipefail
exec > /tmp/chiye-10443-evidence/musl-build.log 2>&1
echo "START $(date -u +%Y-%m-%dT%H:%M:%SZ)"
export PATH="/tmp/chiye-10443-build/go/bin:${PATH}"
export GOTOOLCHAIN=local
export GOOS=linux
export GOARCH=amd64
export GOMODCACHE=/tmp/chiye-10443-build/modcache
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
export GOSUMDB="${GOSUMDB:-sum.golang.org}"
# read_tag is a host tool. Do not compile it with the musl CC.
unset CC CXX CGO_LDFLAGS
export CGO_ENABLED=0
cd /tmp/chiye-10443-build/src
export GITHUB_ENV=/tmp/chiye-10443-evidence/github_env.txt
: > "$GITHUB_ENV"
go run ./cmd/internal/read_tag --ci --nightly
echo "GITHUB_ENV_CONTENTS"
cat "$GITHUB_ENV"
VERSION=$(sed -n 's/^version=//p' "$GITHUB_ENV")
test -n "$VERSION"
LDFLAGS_SHARED=$(cat release/LDFLAGS)
TAGS="$(cat release/DEFAULT_BUILD_TAGS),with_musl"
export PATH="/home/ubuntu/cronet-go/naiveproxy/src/third_party/llvm-build/Release+Asserts/bin:${PATH}"
export CGO_ENABLED=1
export GOCACHE=/tmp/chiye-10443-build/gocache-musl
cd /home/ubuntu/cronet-go
while IFS= read -r line; do
  key=${line%%=*}
  val=${line#*=}
  export "${key}=${val}"
  printf 'naive_env %s=%s\n' "$key" "$val"
done < <(env -u CC -u CXX -u CGO_LDFLAGS CGO_ENABLED=0 go run ./cmd/build-naive --target=linux/amd64 --libc=musl env)
cd /tmp/chiye-10443-build/src
echo "VERSION=${VERSION}"
echo "TAGS=${TAGS}"
echo "LDFLAGS_SHARED=${LDFLAGS_SHARED}"
echo "CC=${CC}"
echo "CXX=${CXX}"
echo "CGO_LDFLAGS=${CGO_LDFLAGS:-}"
mkdir -p /tmp/chiye-10443-evidence/bin
ldflags="-X github.com/sagernet/sing-box/constant.Version=${VERSION} ${LDFLAGS_SHARED} -s -w -buildid="
echo "ldflags=${ldflags}"
go build -v -trimpath -o /tmp/chiye-10443-evidence/bin/sing-box-musl-a -tags "${TAGS}" -ldflags "${ldflags}" ./cmd/sing-box
echo "BUILD_A_OK $(date -u +%Y-%m-%dT%H:%M:%SZ)"
go build -trimpath -o /tmp/chiye-10443-evidence/bin/sing-box-musl-b -tags "${TAGS}" -ldflags "${ldflags}" ./cmd/sing-box
echo "BUILD_B_OK $(date -u +%Y-%m-%dT%H:%M:%SZ)"
sha256sum /tmp/chiye-10443-evidence/bin/sing-box-musl-a /tmp/chiye-10443-evidence/bin/sing-box-musl-b
cmp /tmp/chiye-10443-evidence/bin/sing-box-musl-a /tmp/chiye-10443-evidence/bin/sing-box-musl-b && echo REPRO_MATCH
file /tmp/chiye-10443-evidence/bin/sing-box-musl-a
ldd /tmp/chiye-10443-evidence/bin/sing-box-musl-a || true
"${PATH%%:*}/go" version -m /tmp/chiye-10443-evidence/bin/sing-box-musl-a || /tmp/chiye-10443-build/go/bin/go version -m /tmp/chiye-10443-evidence/bin/sing-box-musl-a
echo "END $(date -u +%Y-%m-%dT%H:%M:%SZ)"
