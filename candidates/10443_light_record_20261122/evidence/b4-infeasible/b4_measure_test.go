//go:build linux

package diag10443

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestB4LowerBoundProbe(t *testing.T) {
	fmt.Printf("CONST maxBytes=%d fixedBudget=%d recordSize=%d maxErrors=%d exportFrame=%d gateScratch=%d index=%d maxInflight=%d controlHeapLimit=%d\n",
		maxBytes, fixedBudget(), recordSize, maxErrors, exportFrameSize, gateScratchSize, indexOverhead, maxInflight(), controlHeapLimit)
	fmt.Printf("CONST sum_fixed_plus_slots=%d\n", fixedBudget()+maxInflight()*recordSize)
	resetForTest()
	dir, err := os.MkdirTemp("/tmp", "b4m")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writePass(dir)
	pointGate(dir)
	setNow(nil)
	report("before_start")
	if err := start(dir); err != nil {
		t.Fatal(err)
	}
	defer resetForTest()
	report("after_start_listener")
	sock := filepath.Join(dir, sockName)
	hold := func() {
		cmd := exec.Command("sudo", "-n", "python3", "-c",
			"import socket,sys,time\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\ns.connect(sys.argv[1])\ntime.sleep(3)\n",
			sock)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	}
	hold()
	time.Sleep(150 * time.Millisecond)
	report("one_root_handler_blocked")
	hold()
	time.Sleep(150 * time.Millisecond)
	report("two_root_handlers_blocked")
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	printSockBuf(t, c, "client_socket")
}

func report(label string) {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("MEAS %s goroutines=%d HeapAlloc=%d HeapInuse=%d StackInuse=%d StackSys=%d TotalAlloc=%d Mallocs=%d\n",
		label, runtime.NumGoroutine(), m.HeapAlloc, m.HeapInuse, m.StackInuse, m.StackSys, m.TotalAlloc, m.Mallocs)
}

func printSockBuf(t *testing.T, c *net.UnixConn, label string) {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var rcv, snd int
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		rcv, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		if gerr != nil {
			return
		}
		snd, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	}); err != nil || gerr != nil {
		t.Fatalf("%s sockopt %v %v", label, err, gerr)
	}
	fmt.Printf("SOCK %s SO_RCVBUF=%d SO_SNDBUF=%d\n", label, rcv, snd)
}
