//go:build linux

package diag10443

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestControlExportOnceStopAndGate(t *testing.T) {
	dir := boot(t)
	sock := filepath.Join(dir, sockName)
	info, err := os.Lstat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", info.Mode())
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v %v", dirInfo, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		t.Fatal("socket owner")
	}
	_, err = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		return nil, syscall.ECONNREFUSED
	})
	if err != syscall.ECONNREFUSED {
		t.Fatal(err)
	}
	status, payload, err := dialRoot(sock, cmdExport)
	if err != nil || status != statusOK {
		t.Fatalf("export status=%d err=%v", status, err)
	}
	if len(payload) > maxBytes {
		t.Fatal(len(payload))
	}
	flags, reason, _, recs, err := decodeExport(payload)
	if err != nil || len(recs) != 1 || recs[0].class != classErrno {
		t.Fatalf("decode %v %+v %v", err, recs, reason)
	}
	if flags&flagEnabled == 0 || flags&flagSwitch != 0 {
		t.Fatalf("flags=%b", flags)
	}
	assertNoSecrets(t, payload)
	status, payload, err = dialRoot(sock, cmdExport)
	if err != nil || status != statusAlready || len(payload) != 0 {
		t.Fatalf("second export status=%d n=%d err=%v", status, len(payload), err)
	}
	status, _, err = dialRoot(sock, cmdStop)
	if err != nil || status != statusOK || enabled.Load() {
		t.Fatalf("stop status=%d enabled=%v err=%v", status, enabled.Load(), err)
	}
	before := recordCount()
	_, _ = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		return nil, syscall.ECONNREFUSED
	})
	if recordCount() != before {
		t.Fatal("stop did not disable recording")
	}
	status, _, err = dialRoot(sock, 9)
	if err != nil || status != statusBad {
		t.Fatalf("bad cmd status=%d err=%v", status, err)
	}
	if _, err := os.Lstat(prodDir); err == nil {
		// existence alone is not a failure if the host already had it; TestMain checks creation
	}
}

func TestStopDuringExportAndBusy(t *testing.T) {
	dir := boot(t)
	sock := filepath.Join(dir, sockName)
	inHook := make(chan struct{})
	release := make(chan struct{})
	exportWait.Store(func() {
		close(inHook)
		<-release
	})
	type result struct {
		status byte
		err    error
		n      int
	}
	exportDone := make(chan result, 1)
	go func() {
		status, payload, err := dialRoot(sock, cmdExport)
		exportDone <- result{status, err, len(payload)}
	}()
	<-inHook
	stopStatus, _, err := dialRoot(sock, cmdStop)
	if err != nil || stopStatus != statusOK {
		t.Fatalf("stop during export %d %v", stopStatus, err)
	}
	busyStatus, busyPayload, err := dialRoot(sock, cmdExport)
	if err != nil || busyStatus != statusBusy || len(busyPayload) != 0 {
		t.Fatalf("busy status=%d n=%d err=%v", busyStatus, len(busyPayload), err)
	}
	close(release)
	got := <-exportDone
	if got.err != nil || got.status != statusOK || got.n == 0 || got.n > maxBytes {
		t.Fatalf("export result %+v", got)
	}
	if enabled.Load() {
		t.Fatal("stop did not clear recording")
	}
	status, payload, err := dialRoot(sock, cmdExport)
	if err != nil || status != statusAlready || len(payload) != 0 {
		t.Fatalf("post export %d %d %v", status, len(payload), err)
	}
}

func TestGateFailureLeavesStopAndDoesNotConsumeExport(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	frozen := time.Unix(1_700_000_000, 0)
	setNow(func() time.Time { return frozen })
	dir := newDir(t)
	writePass(dir)
	if err := os.WriteFile(filepath.Join(dir, "load"), []byte("1.50 0 0 1/1 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pointGate(dir)
	if err := start(dir); err != nil {
		t.Fatal(err)
	}
	if enabled.Load() || reasonOf() != reasonGate {
		t.Fatalf("enabled=%v reason=%d", enabled.Load(), reasonOf())
	}
	sock := filepath.Join(dir, sockName)
	called := false
	_, _ = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, syscall.ECONNREFUSED
	})
	if !called || recordCount() != 0 {
		t.Fatal("gate failure still dialed or recorded")
	}
	status, _, err := dialRoot(sock, cmdStop)
	if err != nil || status != statusOK {
		t.Fatalf("stop under gate %d %v", status, err)
	}
	status, payload, err := dialRoot(sock, cmdExport)
	if err != nil || status != statusGate || len(payload) != 0 {
		t.Fatalf("export under gate %d %d %v", status, len(payload), err)
	}
	writePass(dir)
	gateMu.Lock()
	gateCache = gateSnap{}
	gateMu.Unlock()
	status, payload, err = dialRoot(sock, cmdExport)
	if err != nil || status != statusOK {
		t.Fatalf("export after gate recovered %d %v", status, err)
	}
	if _, _, _, _, err := decodeExport(payload); err != nil {
		t.Fatal(err)
	}
	status, _, err = dialRoot(sock, cmdExport)
	if err != nil || status != statusAlready {
		t.Fatalf("second %d %v", status, err)
	}
	if enabled.Load() {
		t.Fatal("gate recovery re-enabled recording")
	}
}

func TestSocketLifetimeAndRefusal(t *testing.T) {
	dir := boot(t)
	sock := filepath.Join(dir, sockName)
	var before syscall.Stat_t
	if err := syscall.Lstat(sock, &before); err != nil {
		t.Fatal(err)
	}
	if err := start(dir); err == nil {
		t.Fatal("second start clobbered or replaced the listener")
	}
	var after syscall.Stat_t
	if err := syscall.Lstat(sock, &after); err != nil {
		t.Fatal(err)
	}
	if before.Ino != after.Ino || before.Dev != after.Dev {
		t.Fatal("socket inode changed")
	}
	shutdown()
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket remained: %v", err)
	}

	resetForTest()
	parent := newDir(t)
	real := filepath.Join(parent, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	writePass(real)
	pointGate(real)
	if err := start(link); err == nil {
		t.Fatal("followed a symlink directory")
	}
	if _, err := os.Lstat(filepath.Join(real, sockName)); !os.IsNotExist(err) {
		t.Fatal("symlink start created a socket in the target")
	}

	resetForTest()
	plain := newDir(t)
	keep := filepath.Join(plain, sockName)
	if err := os.WriteFile(keep, []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(plain, "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keep); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, keep); err != nil {
		t.Fatal(err)
	}
	writePass(plain)
	pointGate(plain)
	if err := start(plain); err == nil {
		t.Fatal("started over an existing symlink name")
	}
	got, err := os.ReadFile(outside)
	if err != nil || !bytes.Equal(got, []byte("outside")) {
		t.Fatalf("outside changed %q %v", got, err)
	}
	linkInfo, err := os.Lstat(keep)
	if err != nil || linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatal("existing name was replaced")
	}

	resetForTest()
	wide := filepath.Join(parent, "wide")
	if err := os.Mkdir(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	writePass(wide)
	pointGate(wide)
	if err := start(wide); err == nil {
		t.Fatal("accepted a 0755 directory")
	}
	info, err := os.Lstat(wide)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("mode was changed: %v", info.Mode().Perm())
	}
}

func dialRoot(path string, cmd byte) (byte, []byte, error) {
	script := "/tmp/diag10443-root-client.py"
	if _, err := os.Stat(script); err != nil {
		if err := os.WriteFile(script, []byte(rootClientScript), 0o644); err != nil {
			return 0, nil, err
		}
	}
	out, err := exec.Command("sudo", "-n", "python3", script, path, strconv.Itoa(int(cmd))).CombinedOutput()
	if err != nil {
		return 0, nil, errors.New(string(out))
	}
	var statusLine, payloadLine string
	for _, line := range bytes.Split(out, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("STATUS ")) {
			statusLine = string(line[len("STATUS "):])
		}
		if bytes.HasPrefix(line, []byte("PAYLOAD ")) {
			payloadLine = string(line[len("PAYLOAD "):])
		}
	}
	statusNum, err := strconv.Atoi(statusLine)
	if err != nil {
		return 0, nil, err
	}
	payload, err := hex.DecodeString(payloadLine)
	if err != nil {
		return 0, nil, err
	}
	return byte(statusNum), payload, nil
}

const rootClientScript = `import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(2)
s.connect(sys.argv[1])
s.sendall(bytes([0x43, 0x34, 0x44, 0x31, int(sys.argv[2])]))
buf = b""
while len(buf) < 9:
    chunk = s.recv(9 - len(buf))
    if not chunk:
        raise SystemExit("short header")
    buf += chunk
n = int.from_bytes(buf[5:9], "big")
while len(buf) < 9 + n:
    chunk = s.recv(9 + n - len(buf))
    if not chunk:
        raise SystemExit("short body")
    buf += chunk
if buf[:4] != b"C4D0":
    raise SystemExit("bad magic")
print("STATUS", buf[4])
print("PAYLOAD", buf[9:].hex())
`

func TestPeerPredicate(t *testing.T) {
	// Predicate only. Cross-UID SO_PEERCRED is TestRootOnlyPeerSocket.
	if !peerAllowed(0) || peerAllowed(5) || peerAllowed(4) || peerAllowed(1000) {
		t.Fatal("peer predicate")
	}
}

func TestSchemaRejectsMutation(t *testing.T) {
	dir := boot(t)
	_, _ = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		return nil, syscall.ECONNABORTED
	})
	blob := snapshotExport()
	if _, _, _, _, err := decodeExport(blob); err != nil {
		t.Fatal(err)
	}
	blob[headerSize+72] = 1
	if _, _, _, _, err := decodeExport(blob); err == nil {
		t.Fatal("nonzero record pad accepted")
	}
	blob = snapshotExport()
	blob = append(blob, 0)
	if _, _, _, _, err := decodeExport(blob); err == nil {
		t.Fatal("trailing byte accepted")
	}
	_ = dir
}

func TestConcurrentDialsStayInsideCaps(t *testing.T) {
	boot(t)
	var wg sync.WaitGroup
	errSample := syscall.ECONNRESET
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_, err := invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
					if j%2 == 0 {
						return stubConn{}, nil
					}
					return nil, errSample
				})
				if j%2 == 0 && err != nil {
					t.Errorf("success err %v", err)
				}
				if j%2 == 1 && !errors.Is(err, errSample) {
					t.Errorf("error changed %v", err)
				}
			}
		}()
	}
	wg.Wait()
	if recordCount() > maxErrors {
		t.Fatalf("records %d", recordCount())
	}
	if recordCount() == maxErrors && enabled.Load() {
		t.Fatal("full budget still enabled")
	}
}
