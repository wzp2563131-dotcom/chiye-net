//go:build linux

package diag10443

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestExpiryDuringGateDiffersFromInner(t *testing.T) {
	dir := bootLive(t)
	_ = dir
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	gatePause.Store(func() {
		once.Do(func() { close(entered) })
		<-release
	})
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	var got context.Context
	done := make(chan error, 1)
	go func() {
		_, err := invoke(ctx, "tcp", targetAddr, func(c context.Context, _, _ string) (net.Conn, error) {
			got = c
			return nil, c.Err()
		})
		done <- err
	}()
	<-entered
	waitDeadline(t, ctx)
	close(release)
	err := <-done
	if err != context.DeadlineExceeded || got != ctx {
		t.Fatalf("gate-wait dial err=%v same=%v", err, got == ctx)
	}
	rec := onlyRecord(t)
	if rec.entryCtx != ctxNil || rec.preCtx != ctxDeadline || rec.retCtx != ctxDeadline {
		t.Fatalf("gate-wait sample %+v", rec)
	}
	if rec.preMono < rec.entryMono || rec.retMono < rec.preMono {
		t.Fatalf("gate-wait times %+v", rec)
	}

	resetKeepGate(t)
	gatePause.Store(func() {})
	ctx, cancel = context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	innerEntered := make(chan struct{})
	innerRelease := make(chan struct{})
	go func() {
		_, err = invoke(ctx, "tcp", targetAddr, func(c context.Context, _, _ string) (net.Conn, error) {
			if c.Err() != nil {
				t.Errorf("pre-inner ctx already %v", c.Err())
			}
			close(innerEntered)
			<-innerRelease
			return nil, c.Err()
		})
		done <- err
	}()
	<-innerEntered
	waitDeadline(t, ctx)
	close(innerRelease)
	err = <-done
	if err != context.DeadlineExceeded {
		t.Fatal(err)
	}
	rec = onlyRecord(t)
	if rec.entryCtx != ctxNil || rec.preCtx != ctxNil || rec.retCtx != ctxDeadline {
		t.Fatalf("inner-wait sample %+v", rec)
	}

	resetKeepGate(t)
	_, err = invoke(context.Background(), "tcp", targetAddr, func(c context.Context, _, _ string) (net.Conn, error) {
		if c.Err() != nil {
			t.Errorf("live ctx %v", c.Err())
		}
		return nil, syscall.ECONNREFUSED
	})
	if err != syscall.ECONNREFUSED {
		t.Fatal(err)
	}
	rec = onlyRecord(t)
	if rec.entryCtx != ctxNil || rec.preCtx != ctxNil || rec.retCtx != ctxNil || rec.class != classErrno {
		t.Fatalf("live errno sample %+v", rec)
	}
}

func TestExportGateFailureLatchesAndBusyDoesNot(t *testing.T) {
	dir := boot(t)
	sock := filepath.Join(dir, sockName)
	gateMu.Lock()
	gateBusy = true
	gateCache = gateSnap{}
	gateMu.Unlock()
	status, payload, err := dialRoot(sock, cmdExport)
	if err != nil || status != statusBusy || len(payload) != 0 {
		t.Fatalf("busy status=%d n=%d err=%v", status, len(payload), err)
	}
	if !enabled.Load() || stopped() {
		t.Fatal("busy latched a stop")
	}
	gateMu.Lock()
	gateBusy = false
	gateMu.Unlock()

	if err := os.WriteFile(filepath.Join(dir, "load"), []byte("9.00 0 0 1/1 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gateMu.Lock()
	gateCache = gateSnap{}
	gateMu.Unlock()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
			return nil, syscall.ECONNRESET
		})
	}()
	var exportStatus byte
	var exportErr error
	go func() {
		defer wg.Done()
		exportStatus, _, exportErr = dialRoot(sock, cmdExport)
	}()
	wg.Wait()
	if exportErr != nil || exportStatus != statusGate {
		t.Fatalf("export status=%d err=%v", exportStatus, exportErr)
	}
	if enabled.Load() || reasonOf() != reasonGate || exported() {
		t.Fatalf("enabled=%v reason=%d exported=%v", enabled.Load(), reasonOf(), exported())
	}
	if recordCount() != 0 {
		t.Fatal("recorded after export gate failure")
	}
	writePass(dir)
	gateMu.Lock()
	gateCache = gateSnap{}
	gateMu.Unlock()
	_, _ = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		return nil, syscall.ECONNRESET
	})
	if enabled.Load() || recordCount() != 0 {
		t.Fatal("healthy gate revived recording")
	}
	status, payload, err = dialRoot(sock, cmdExport)
	if err != nil || status != statusOK || len(payload) == 0 || len(payload) > maxBytes {
		t.Fatalf("later export %d %d %v", status, len(payload), err)
	}
	status, _, err = dialRoot(sock, cmdExport)
	if err != nil || status != statusAlready {
		t.Fatalf("second export %d %v", status, err)
	}
	status, _, err = dialRoot(sock, cmdStop)
	if err != nil || status != statusOK {
		t.Fatalf("stop %d %v", status, err)
	}
}

func TestExactCapPermanentStopAndHeap(t *testing.T) {
	dir := boot(t)
	sock := filepath.Join(dir, sockName)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	n := 0
	for {
		if _, ok := reserve(); !ok {
			break
		}
		n++
		if n > maxInflight()+2 {
			t.Fatal("reserve did not stop")
		}
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if n != maxInflight() {
		t.Fatalf("reserved %d want %d", n, maxInflight())
	}
	mu.Lock()
	reserved := st.reserved
	mu.Unlock()
	if reserved != maxBytes || !stopped() || reasonOf() != reasonSize || enabled.Load() {
		t.Fatalf("reserved=%d stopped=%v reason=%d enabled=%v", reserved, stopped(), reasonOf(), enabled.Load())
	}
	if after.Mallocs != before.Mallocs {
		t.Fatalf("filling the cap allocated %d times", after.Mallocs-before.Mallocs)
	}
	if after.TotalAlloc-before.TotalAlloc > uint64(controlHeapLimit) {
		t.Fatalf("cap fill heap delta %d", after.TotalAlloc-before.TotalAlloc)
	}
	status, payload, err := dialRoot(sock, cmdExport)
	if err != nil || status != statusOK {
		t.Fatalf("export at cap %d %v", status, err)
	}
	var exportedStats runtime.MemStats
	runtime.ReadMemStats(&exportedStats)
	if exportedStats.TotalAlloc-before.TotalAlloc > uint64(maxBytes+controlHeapLimit) {
		t.Fatalf("export heap delta %d", exportedStats.TotalAlloc-before.TotalAlloc)
	}
	_ = payload
	for i := 0; i < n; i++ {
		releaseInflight()
	}
	if enabled.Load() || !stopped() || reasonOf() != reasonSize {
		t.Fatal("release cleared the size stop")
	}
	if _, ok := reserve(); ok {
		t.Fatal("reserve after release")
	}

	resetForTest()
	dir = boot(t)
	for i := 0; i < maxErrors; i++ {
		_, err := invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
			return nil, syscall.EPIPE
		})
		if err != syscall.EPIPE {
			t.Fatal(err)
		}
	}
	if recordCount() != maxErrors || enabled.Load() || reasonOf() != reasonErrors {
		t.Fatalf("errors=%d enabled=%v reason=%d", recordCount(), enabled.Load(), reasonOf())
	}
	status, _, err = dialRoot(filepath.Join(dir, sockName), cmdExport)
	if err != nil || status != statusOK {
		t.Fatalf("export at error cap %d %v", status, err)
	}
	_, _ = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		return nil, syscall.EPIPE
	})
	if recordCount() != maxErrors || enabled.Load() {
		t.Fatal("error cap revived")
	}
}

func TestRootOnlyPeerSocket(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("service side of this test must be non-root")
	}
	dir := boot(t)
	sock := filepath.Join(dir, sockName)
	script := filepath.Join(dir, "peer.py")
	if err := os.WriteFile(script, []byte(peerScript), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := dialCommand(sock, cmdStop); err == nil {
		t.Fatal("same-uid non-root client completed a STOP frame")
	}
	if !enabled.Load() || stopped() {
		t.Fatal("same-uid client changed recording")
	}
	out, err := exec.Command("sudo", "-n", "-u", "nobody", "python3", script, sock, "1").CombinedOutput()
	if err == nil {
		t.Fatalf("other uid was not denied: %s", out)
	}
	if !enabled.Load() {
		t.Fatal("other uid stopped recording")
	}
	out, err = exec.Command("sudo", "-n", "python3", script, sock, "2").CombinedOutput()
	if err != nil || !bytesContains(out, []byte("STATUS 0")) {
		t.Fatalf("root export: %v %s", err, out)
	}
	out, err = exec.Command("sudo", "-n", "python3", script, sock, "1").CombinedOutput()
	if err != nil || !bytesContains(out, []byte("STATUS 0")) {
		t.Fatalf("root stop: %v %s", err, out)
	}
	if enabled.Load() {
		t.Fatal("root STOP did not disable recording")
	}
}

const peerScript = `import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(2)
s.connect(sys.argv[1])
s.sendall(bytes([0x43, 0x34, 0x44, 0x31, int(sys.argv[2])]))
data = s.recv(9)
if len(data) < 5 or data[:4] != b"C4D0":
    raise SystemExit("bad frame")
print("STATUS", data[4])
`

func bootLive(t *testing.T) string {
	t.Helper()
	resetForTest()
	setNow(nil)
	dir := newDir(t)
	writePass(dir)
	pointGate(dir)
	if err := start(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gatePause.Store(func() {}); resetForTest() })
	if !enabled.Load() {
		t.Fatal("recording did not arm")
	}
	return dir
}

func waitDeadline(t *testing.T, ctx context.Context) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("missing deadline")
	}
	time.Sleep(time.Until(deadline) + 30*time.Millisecond)
	if ctx.Err() == nil {
		t.Fatal("deadline did not fire")
	}
}

func stopped() bool {
	mu.Lock()
	defer mu.Unlock()
	return st.stopped
}

func exported() bool {
	mu.Lock()
	defer mu.Unlock()
	return st.exported
}
