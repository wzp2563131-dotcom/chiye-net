package diag10443

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"
)

func TestABOverhead(t *testing.T) {
	resetForTest()
	t.Cleanup(resetForTest)
	frozen := time.Now()
	setNow(func() time.Time { return frozen })
	dir := newDir(t)
	writePass(dir)
	pointGate(dir)
	if err := enableRecording(); err != nil {
		t.Fatal(err)
	}
	if !enabled.Load() {
		t.Fatal("measurement did not arm")
	}
	ctx := context.Background()
	fn := WrapDialer(func(context.Context, string, string) (net.Conn, error) {
		return stubConn{}, nil
	})
	for i := 0; i < 256; i++ {
		enabled.Store(false)
		_, _ = fn(ctx, "tcp", targetAddr)
		enabled.Store(true)
		_, _ = fn(ctx, "tcp", targetAddr)
	}
	if recordCount() != 0 {
		t.Fatal("success path retained a record")
	}
	const n = 4096
	off := make([]int64, n)
	on := make([]int64, n)
	delta := make([]int64, n)
	for i := 0; i < n; i++ {
		enabled.Store(false)
		t0 := time.Now()
		_, _ = fn(ctx, "tcp", targetAddr)
		off[i] = time.Since(t0).Nanoseconds()
		enabled.Store(true)
		t1 := time.Now()
		_, _ = fn(ctx, "tcp", targetAddr)
		on[i] = time.Since(t1).Nanoseconds()
		delta[i] = on[i] - off[i]
	}
	enabled.Store(false)
	offAlloc := testing.AllocsPerRun(1000, func() {
		_, _ = fn(ctx, "tcp", targetAddr)
	})
	enabled.Store(true)
	onAlloc := testing.AllocsPerRun(1000, func() {
		_, _ = fn(ctx, "tcp", targetAddr)
	})
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < n; i++ {
		_, _ = fn(ctx, "tcp", targetAddr)
	}
	runtime.ReadMemStats(&after)

	cold := make([]int64, 32)
	for i := range cold {
		gateMu.Lock()
		gateCache = gateSnap{}
		gateMu.Unlock()
		t0 := time.Now()
		_, _ = fn(ctx, "tcp", targetAddr)
		cold[i] = time.Since(t0).Nanoseconds()
	}

	hostLoad, _ := os.ReadFile("/proc/loadavg")
	hostPSI, _ := os.ReadFile("/proc/pressure/cpu")
	hostMem, _ := os.ReadFile("/proc/meminfo")
	model := readModel()
	summary := map[string]any{
		"design":                   "paired in-process success dial, same closure, disabled then enabled, fake inner returns immediately",
		"not":                      "not production host overhead, not historical 10443 cause, not a 1ms proof",
		"samples":                  n,
		"warmup":                   256,
		"cold_gate_samples":        len(cold),
		"disabled_ns":              stats(off),
		"enabled_ns":               stats(on),
		"delta_ns":                 stats(delta),
		"cold_gate_ns":             stats(cold),
		"allocs_per_disabled_call": offAlloc,
		"allocs_per_enabled_call":  onAlloc,
		"batch_mallocs":            after.Mallocs - before.Mallocs,
		"batch_total_alloc":        after.TotalAlloc - before.TotalAlloc,
		"batch_num_gc":             after.NumGC - before.NumGC,
		"go":                       runtime.Version(),
		"goos":                     runtime.GOOS,
		"goarch":                   runtime.GOARCH,
		"num_cpu":                  runtime.NumCPU(),
		"gomaxprocs":               runtime.GOMAXPROCS(0),
		"model":                    model,
		"loadavg":                  trimOne(hostLoad),
		"psi":                      trimOne(hostPSI),
		"meminfo_head":             trimHead(hostMem, 200),
	}
	raw, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(raw))
	if path := os.Getenv("DIAG10443_AB_OUT"); path != "" {
		if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if path := os.Getenv("DIAG10443_AB_RAW"); path != "" {
		buf := make([]byte, len(delta)*8)
		for i, v := range delta {
			binary.LittleEndian.PutUint64(buf[i*8:], uint64(v))
		}
		if err := os.WriteFile(path, buf, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func stats(samples []int64) map[string]int64 {
	cp := append([]int64(nil), samples...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return map[string]int64{
		"min": cp[0],
		"p50": cp[len(cp)/2],
		"p90": cp[len(cp)*90/100],
		"p99": cp[len(cp)*99/100],
		"max": cp[len(cp)-1],
	}
}

func readModel() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	const key = "model name"
	text := string(b)
	for i := 0; i+len(key) < len(text); i++ {
		if text[i:i+len(key)] == key {
			line := text[i:]
			if nl := indexByte(line, '\n'); nl >= 0 {
				line = line[:nl]
			}
			return line
		}
	}
	return ""
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func trimOne(b []byte) string {
	if len(b) > 180 {
		b = b[:180]
	}
	return string(b)
}

func trimHead(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}
