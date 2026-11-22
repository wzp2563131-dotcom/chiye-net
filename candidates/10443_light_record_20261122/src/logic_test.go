package diag10443

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"
)

type stubConn struct{}

func (stubConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (stubConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (stubConn) Close() error                     { return nil }
func (stubConn) LocalAddr() net.Addr              { return nil }
func (stubConn) RemoteAddr() net.Addr             { return nil }
func (stubConn) SetDeadline(time.Time) error      { return nil }
func (stubConn) SetReadDeadline(time.Time) error  { return nil }
func (stubConn) SetWriteDeadline(time.Time) error { return nil }

type trapErr struct{ calls *int }

func (t trapErr) Error() string {
	*t.calls++
	return "SECRET-TRAP-TEXT-example.com"
}

func (t trapErr) Unwrap() error { return syscall.ECONNREFUSED }

type boomErr struct{}

func (boomErr) Error() string { panic("SECRET-BOOM") }
func (boomErr) Unwrap() error { panic("SECRET-BOOM") }

type weirdCtx struct{ context.Context }

func (weirdCtx) Err() error                  { return errors.New("SECRET-WEIRD") }
func (weirdCtx) Deadline() (time.Time, bool) { return time.Time{}, false }

func TestMain(m *testing.M) {
	_, beforeErr := os.Lstat(prodDir)
	code := m.Run()
	_, afterErr := os.Lstat(prodDir)
	if beforeErr != nil && afterErr == nil {
		os.Stderr.WriteString("tests created " + prodDir + "\n")
		os.Exit(2)
	}
	os.Exit(code)
}

func TestApprovedSwitchIsOff(t *testing.T) {
	if approvedSwitch {
		t.Fatal("frozen candidate must not arm itself")
	}
	if prodDir != "/run/chiye-net" || sockName != "10443-diag.sock" {
		t.Fatal("control path changed")
	}
}

func TestSchemaTypesHaveNoStrings(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(sample{}), reflect.TypeOf(classified{}), reflect.TypeOf(state{})} {
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).Type.Kind() == reflect.String {
				t.Fatalf("%s.%s is a string", typ.Name(), typ.Field(i).Name)
			}
		}
	}
}

func TestDisabledPathDoesNotRecordOrAllocate(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	var idCalls int
	SetConnIDFunc(func(context.Context) (uint32, bool) {
		idCalls++
		return 9, true
	})
	innerCalls := 0
	inner := func(context.Context, string, string) (net.Conn, error) {
		innerCalls++
		return stubConn{}, nil
	}
	fn := WrapDialer(inner)
	allocs := testing.AllocsPerRun(200, func() {
		_, _ = fn(context.Background(), "tcp", targetAddr)
	})
	if allocs != 0 {
		t.Fatalf("disabled allocs=%v", allocs)
	}
	if innerCalls != 201 { // AllocsPerRun once plus 200
		t.Fatalf("inner calls=%d", innerCalls)
	}
	if idCalls != 0 || recordCount() != 0 || enabled.Load() {
		t.Fatal("disabled path recorded or looked up an id")
	}
}

func invoke(ctx context.Context, network, addr string, inner DialFunc) (net.Conn, error) {
	return WrapDialer(inner)(ctx, network, addr)
}

func TestSuccessDiscardAndNonTarget(t *testing.T) {
	boot(t)
	var conn stubConn
	out, err := invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		return conn, nil
	})
	if err != nil || out != conn {
		t.Fatalf("success changed result %#v %v", out, err)
	}
	if recordCount() != 0 {
		t.Fatal("success was retained")
	}
	targets := [][2]string{
		{"tcp", "127.0.0.1:8443"},
		{"tcp", "127.0.0.1:443"},
		{"tcp", "127.0.0.2:10443"},
		{"tcp6", "127.0.0.1:10443"},
		{"udp", "127.0.0.1:10443"},
		{"TCP", "127.0.0.1:10443"},
		{"tcp", "[::1]:10443"},
		{"tcp", "127.0.0.1:10443 "},
	}
	for _, item := range targets {
		called := false
		_, _ = invoke(context.Background(), item[0], item[1], func(context.Context, string, string) (net.Conn, error) {
			called = true
			return nil, errors.New("SECRET-OTHER")
		})
		if !called {
			t.Fatalf("inner skipped for %s %s", item[0], item[1])
		}
	}
	if recordCount() != 0 {
		t.Fatal("non-target produced a record")
	}
}

func TestExpiredCancelAndUnknownContext(t *testing.T) {
	boot(t)
	expired, cancel := context.WithDeadline(context.Background(), time.Unix(10, 0))
	defer cancel()
	if expired.Err() != context.DeadlineExceeded {
		t.Fatal("fixture context is not expired")
	}
	called := false
	ret, err := invoke(expired, "tcp", targetAddr, func(ctx context.Context, _, _ string) (net.Conn, error) {
		called = true
		if ctx != expired {
			t.Fatal("expired ctx was replaced")
		}
		if ctx.Err() != context.DeadlineExceeded {
			t.Fatal("hook cleared the deadline")
		}
		return nil, ctx.Err()
	})
	if !called || err != context.DeadlineExceeded || ret != nil {
		t.Fatalf("expired dial changed behavior called=%v err=%v", called, err)
	}
	rec := onlyRecord(t)
	if rec.entryCtx != ctxDeadline || rec.retCtx != ctxDeadline || rec.entryHas != 1 || rec.entryRemain >= 0 {
		t.Fatalf("expired snapshot %+v", rec)
	}
	if rec.class != classDeadline {
		t.Fatalf("class=%d", rec.class)
	}
	resetKeepGate(t)

	canceled, cancel2 := context.WithCancel(context.Background())
	cancel2()
	_, err = invoke(canceled, "tcp", targetAddr, func(ctx context.Context, _, _ string) (net.Conn, error) {
		if ctx.Err() != context.Canceled {
			t.Fatal(ctx.Err())
		}
		return nil, ctx.Err()
	})
	if err != context.Canceled {
		t.Fatal(err)
	}
	rec = onlyRecord(t)
	if rec.entryCtx != ctxCanceled || rec.class != classCanceled || rec.entryHas != 0 || rec.entryRemain != 0 {
		t.Fatalf("cancel snapshot %+v", rec)
	}

	resetKeepGate(t)
	weird := weirdCtx{Context: context.Background()}
	_, err = invoke(weird, "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("SECRET-PLAIN")
	})
	if err == nil {
		t.Fatal("missing error")
	}
	rec = onlyRecord(t)
	if rec.entryCtx != ctxUnknown || rec.class != classUnknown || rec.errno != 0 {
		t.Fatalf("unknown snapshot %+v", rec)
	}
	assertNoSecrets(t, snapshotExport())
}

func TestTypedClassBeforeFlatten(t *testing.T) {
	boot(t)
	calls := 0
	trap := trapErr{calls: &calls}
	_, err := invoke(context.Background(), "tcp4", targetAddr, func(ctx context.Context, network, addr string) (net.Conn, error) {
		if ctx == nil || network != "tcp4" || addr != targetAddr {
			t.Fatal("inner arguments changed")
		}
		return nil, trap
	})
	if err != trap || calls != 0 {
		t.Fatalf("err identity or Error() calls=%d", calls)
	}
	rec := onlyRecord(t)
	if rec.class != classErrno || rec.errno != int32(syscall.ECONNREFUSED) || rec.wrapper != wrapperNone {
		t.Fatalf("pre-flatten class %+v", rec)
	}
	flat := errors.New(err.Error())
	var errno syscall.Errno
	if errors.As(flat, &errno) {
		t.Fatal("flattened error kept the errno type")
	}
	if calls != 1 {
		t.Fatal("test did not flatten via Error")
	}
	op := &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.50"), Port: 9},
		Err:  syscall.ECONNREFUSED,
	}
	resetKeepGate(t)
	SetConnIDFunc(func(context.Context) (uint32, bool) { return 0xA1B2C3D4, true })
	outErr := op
	_, err = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		return nil, outErr
	})
	if err != outErr {
		t.Fatal("op error replaced")
	}
	rec = onlyRecord(t)
	if rec.class != classErrno || rec.wrapper != wrapperOpError || rec.op != opDial || rec.connPresent != 1 || rec.connID != 0xA1B2C3D4 {
		t.Fatalf("op snapshot %+v", rec)
	}
	if rec.entryMono > rec.preMono || rec.preMono > rec.retMono {
		t.Fatalf("mono order %+v", rec)
	}
	blob := snapshotExport()
	assertNoSecrets(t, blob)
	if bytesContains(blob, []byte("203.0.113.50")) || bytesContains(blob, []byte("dial")) || bytesContains(blob, []byte("127.0.0.1")) {
		t.Fatal("export leaked address or op text")
	}

	resetKeepGate(t)
	_, err = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		return nil, boomErr{}
	})
	if err != (boomErr{}) {
		t.Fatal(err)
	}
	rec = onlyRecord(t)
	if rec.class != classUnknown {
		t.Fatalf("panic classify class=%d", rec.class)
	}
}

func TestTFOAndNonTFOBranches(t *testing.T) {
	boot(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &stubConn{}
	var got context.Context
	out, err := invoke(ctx, "tcp", targetAddr, func(c context.Context, _, _ string) (net.Conn, error) {
		got = c
		// The TFO slow-open path detaches inside the dialer, after this hook.
		_ = context.WithoutCancel(c)
		return conn, nil
	})
	if err != nil || out != conn || got != ctx {
		t.Fatalf("TFO-shaped return changed err=%v same=%v", err, got == ctx)
	}
	if recordCount() != 0 {
		t.Fatal("TFO early nil was stored; a later connect error is outside this hook")
	}
	later := context.DeadlineExceeded
	_ = later
	if recordCount() != 0 {
		t.Fatal("later connect error was recorded without a second dial return")
	}

	op := &net.OpError{Op: "dial", Err: syscall.ETIMEDOUT}
	out, err = invoke(ctx, "tcp", targetAddr, func(c context.Context, _, _ string) (net.Conn, error) {
		if c != ctx {
			t.Fatal("non-TFO ctx replaced")
		}
		if c.Err() != nil {
			t.Fatal("hook canceled the caller")
		}
		return nil, op
	})
	if err != op || out != nil {
		t.Fatal("non-TFO result changed")
	}
	rec := onlyRecord(t)
	if rec.class != classErrno || rec.errno != int32(syscall.ETIMEDOUT) {
		t.Fatalf("non-TFO class %+v", rec)
	}
}

func TestBudgetsDoNotRenew(t *testing.T) {
	boot(t)
	sampleErr := syscall.ECONNRESET
	for i := 0; i < maxErrors+2; i++ {
		_, err := invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
			return nil, sampleErr
		})
		if err != sampleErr {
			t.Fatal(err)
		}
	}
	if recordCount() != maxErrors {
		t.Fatalf("records=%d", recordCount())
	}
	if reasonOf() != reasonErrors || enabled.Load() {
		t.Fatalf("reason=%d enabled=%v", reasonOf(), enabled.Load())
	}
	before := recordCount()
	_, _ = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		return nil, sampleErr
	})
	if recordCount() != before || enabled.Load() {
		t.Fatal("error cap renewed")
	}

	resetForTest()
	base := time.Unix(1_700_000_000, 0)
	setNow(func() time.Time { return base })
	dir := newDir(t)
	writePass(dir)
	pointGate(dir)
	if err := start(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resetForTest)
	entered := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	var innerCtx context.Context
	go func() {
		defer wg.Done()
		_, _ = invoke(context.Background(), "tcp", targetAddr, func(ctx context.Context, _, _ string) (net.Conn, error) {
			innerCtx = ctx
			close(entered)
			<-release
			return nil, sampleErr
		})
	}()
	<-entered
	setNow(func() time.Time { return base.Add(maxAge) })
	close(release)
	wg.Wait()
	if innerCtx.Err() != nil {
		t.Fatal("time cap canceled the dial")
	}
	if recordCount() != 0 || reasonOf() != reasonTime {
		t.Fatalf("time cap records=%d reason=%d", recordCount(), reasonOf())
	}
	setNow(func() time.Time { return base })
	_, _ = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		return nil, sampleErr
	})
	if recordCount() != 0 || enabled.Load() {
		t.Fatal("time cap renewed")
	}
}

func TestSizeBudgetFailsClosed(t *testing.T) {
	boot(t)
	limit := maxInflight()
	if limit < 2 {
		t.Fatal(limit)
	}
	hold := make(chan struct{})
	started := make(chan struct{}, limit)
	var wg sync.WaitGroup
	sampleErr := syscall.EPIPE
	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
				started <- struct{}{}
				<-hold
				return nil, sampleErr
			})
		}()
	}
	for i := 0; i < limit; i++ {
		<-started
	}
	mu.Lock()
	held := st.inflight
	mu.Unlock()
	if held != limit {
		t.Fatalf("inflight=%d limit=%d", held, limit)
	}
	entered := false
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
			entered = true
			return nil, sampleErr
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("overflow dial blocked")
	}
	if !entered {
		t.Fatal("overflow skipped the real dial")
	}
	if reasonOf() != reasonSize || enabled.Load() || recordCount() != 0 {
		t.Fatalf("reason=%d enabled=%v", reasonOf(), enabled.Load())
	}
	close(hold)
	wg.Wait()
	if recordCount() != 0 {
		t.Fatalf("size cap stored %d", recordCount())
	}
	_, _ = invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		return nil, sampleErr
	})
	if recordCount() != 0 || enabled.Load() {
		t.Fatal("size cap renewed")
	}
}

func TestGateParserBoundaries(t *testing.T) {
	if !loadOK("0.749 0 0 1/1 1\n") || loadOK("0.750 0 0 1/1 1\n") || loadOK("nope") {
		t.Fatal("load boundary")
	}
	if !psiOK("some avg10=19.999 avg60=0 avg300=0 total=1\n") || psiOK("some avg10=20 avg60=0 avg300=0 total=1\n") || psiOK("full avg10=0 avg60=0 avg300=0 total=1\n") {
		t.Fatal("psi boundary")
	}
	if !memOK("MemAvailable: 131072 kB\n") || memOK("MemAvailable: 131071 kB\n") || memOK("MemAvailable: 999999 MB\n") {
		t.Fatal("mem boundary")
	}
	if readGate(gatePathSet{load: "/no/such-load", psi: "/no/such-psi", mem: "/no/such-mem"}) {
		t.Fatal("unreadable gate passed")
	}
}

func TestNonWhitelistErrnoIsUnknown(t *testing.T) {
	boot(t)
	_, err := invoke(context.Background(), "tcp", targetAddr, func(context.Context, string, string) (net.Conn, error) {
		return nil, syscall.EPERM
	})
	if err != syscall.EPERM {
		t.Fatal(err)
	}
	rec := onlyRecord(t)
	if rec.class != classUnknown || rec.errno != 0 {
		t.Fatalf("%+v", rec)
	}
}

func boot(t *testing.T) string {
	t.Helper()
	resetForTest()
	frozen := time.Unix(1_700_000_000, 0)
	setNow(func() time.Time { return frozen })
	dir := newDir(t)
	writePass(dir)
	pointGate(dir)
	if err := start(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resetForTest)
	if !enabled.Load() {
		t.Fatal("recording did not arm")
	}
	return dir
}

func resetKeepGate(t *testing.T) {
	t.Helper()
	// Drop retained records without discarding the listener or the passing gate.
	mu.Lock()
	st.nrec = 0
	st.errors = 0
	st.dropped = 0
	if st.arena != nil {
		off := indexOverhead + exportFrameSize + gateScratchSize
		for i := 0; i < maxErrors*recordSize; i++ {
			st.arena[off+i] = 0
		}
	}
	mu.Unlock()
}

func newDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "c443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writePass(dir string) {
	_ = os.WriteFile(filepath.Join(dir, "load"), []byte("0.10 0.10 0.10 1/1 1\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "psi"), []byte("some avg10=1.00 avg60=1.00 avg300=1.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "mem"), []byte("MemTotal: 1000000 kB\nMemAvailable: 262144 kB\n"), 0o600)
}

func pointGate(dir string) {
	gateMu.Lock()
	gatePaths = gatePathSet{
		load: filepath.Join(dir, "load"),
		psi:  filepath.Join(dir, "psi"),
		mem:  filepath.Join(dir, "mem"),
	}
	gateCache = gateSnap{}
	gateBusy = false
	gateMu.Unlock()
}

func recordCount() int {
	mu.Lock()
	defer mu.Unlock()
	return st.nrec
}

func reasonOf() uint8 {
	mu.Lock()
	defer mu.Unlock()
	return st.reason
}

func onlyRecord(t *testing.T) sample {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	if st.nrec != 1 {
		t.Fatalf("records=%d", st.nrec)
	}
	rec, err := takeRecord(retainedSlot(0))
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func assertNoSecrets(t *testing.T, blob []byte) {
	t.Helper()
	for _, secret := range []string{
		"SECRET-TRAP-TEXT-example.com",
		"SECRET-WEIRD",
		"SECRET-PLAIN",
		"SECRET-BOOM",
		"SECRET-OTHER",
		"203.0.113.50",
	} {
		if bytesContains(blob, []byte(secret)) {
			t.Fatalf("leaked %s", secret)
		}
	}
}

func bytesContains(b, sub []byte) bool {
	return len(sub) == 0 || (len(b) >= len(sub) && indexBytes(b, sub) >= 0)
}

func indexBytes(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		match := true
		for j := range sub {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
