//go:build linux

package diag10443

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const atSymlinkNoFollow = 0x100

func fstatatNoFollow(dirfd int, name string, st *syscall.Stat_t) error {
	ptr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_NEWFSTATAT, uintptr(dirfd), uintptr(unsafe.Pointer(ptr)), uintptr(unsafe.Pointer(st)), atSymlinkNoFollow, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

var (
	errPerm     = errors.New("diag10443: permission")
	errExists   = errors.New("diag10443: exists")
	errOwner    = errors.New("diag10443: owner")
	errPath     = errors.New("diag10443: path")
	errNotDir   = errors.New("diag10443: not a directory")
	errMismatch = errors.New("diag10443: socket identity")
)

type listenerState struct {
	ln    *net.UnixListener
	dirfd int
	ino   uint64
	dev   uint64
	done  chan struct{}
}

var current listenerState

func start(dir string) error {
	if dir == "" || len(dir) > 80 || len(sockName) > 32 {
		return errPath
	}
	if err := armBudget(); err != nil {
		return err
	}
	if err := listen(dir); err != nil {
		disarmBudget()
		return err
	}
	allow, definitive := gateDecision()
	if !allow {
		if definitive {
			disable(reasonGate)
		}
		return nil
	}
	enabled.Store(true)
	return nil
}

var listenMu sync.Mutex

func listen(dir string) error {
	listenMu.Lock()
	defer listenMu.Unlock()
	if current.ln != nil {
		return errBusy
	}
	dirfd, err := prepareDir(dir, dir == prodDir)
	if err != nil {
		return err
	}
	var existing syscall.Stat_t
	err = fstatatNoFollow(dirfd, sockName, &existing)
	if err == nil {
		_ = syscall.Close(dirfd)
		return errExists
	}
	if !errors.Is(err, syscall.ENOENT) {
		_ = syscall.Close(dirfd)
		return err
	}
	old := syscall.Umask(0o077)
	addr := "/proc/self/fd/" + strconv.Itoa(dirfd) + "/" + sockName
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: addr, Net: "unix"})
	_ = syscall.Umask(old)
	if err != nil {
		_ = syscall.Close(dirfd)
		return err
	}
	ln.SetUnlinkOnClose(false)
	// fstat on the listen fd is the sockfs inode, not the directory entry.
	// Identity is the no-follow directory entry created through this dirfd.
	var nameSt syscall.Stat_t
	if err := fstatatNoFollow(dirfd, sockName, &nameSt); err != nil {
		_ = ln.Close()
		_ = syscall.Close(dirfd)
		return err
	}
	if nameSt.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		_ = ln.Close()
		_ = syscall.Close(dirfd)
		return errMismatch
	}
	ino, dev := nameSt.Ino, nameSt.Dev
	if err := syscall.Fchmodat(dirfd, sockName, 0o600, atSymlinkNoFollow); err != nil {
		_ = ln.Close()
		removeIfIno(dirfd, ino, dev)
		_ = syscall.Close(dirfd)
		return err
	}
	if err := fstatatNoFollow(dirfd, sockName, &nameSt); err != nil {
		_ = ln.Close()
		_ = syscall.Close(dirfd)
		return err
	}
	if nameSt.Ino != ino || nameSt.Dev != dev || nameSt.Mode&syscall.S_IFMT != syscall.S_IFSOCK || nameSt.Mode&0o777 != 0o600 || nameSt.Uid != uint32(os.Geteuid()) {
		_ = ln.Close()
		removeIfIno(dirfd, ino, dev)
		_ = syscall.Close(dirfd)
		return errPerm
	}
	done := make(chan struct{})
	current = listenerState{ln: ln, dirfd: dirfd, ino: ino, dev: dev, done: done}
	go acceptLoop(ln, done)
	return nil
}

func prepareDir(path string, allowCreate bool) (int, error) {
	if allowCreate {
		var st syscall.Stat_t
		err := syscall.Lstat(path, &st)
		if errors.Is(err, syscall.ENOENT) {
			if mkErr := syscall.Mkdir(path, 0o700); mkErr != nil && !errors.Is(mkErr, syscall.EEXIST) {
				return -1, mkErr
			}
		} else if err != nil {
			return -1, err
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		_ = syscall.Close(fd)
		return -1, errNotDir
	}
	if st.Mode&0o777 != 0o700 {
		_ = syscall.Close(fd)
		return -1, errPerm
	}
	if st.Uid != uint32(os.Geteuid()) {
		_ = syscall.Close(fd)
		return -1, errOwner
	}
	return fd, nil
}

func removeIfIno(dirfd int, ino, dev uint64) {
	if dirfd < 0 || ino == 0 {
		return
	}
	var st syscall.Stat_t
	if err := fstatatNoFollow(dirfd, sockName, &st); err != nil {
		return
	}
	if st.Ino != ino || st.Dev != dev || st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return
	}
	_ = syscall.Unlinkat(dirfd, sockName)
}

func acceptLoop(ln *net.UnixListener, done chan struct{}) {
	defer close(done)
	var wg sync.WaitGroup
	defer wg.Wait()
	sem := make(chan struct{}, 2)
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(c *net.UnixConn) {
			defer wg.Done()
			defer func() { <-sem }()
			handleConn(c)
			_ = c.Close()
		}(conn)
	}
}

func handleConn(conn *net.UnixConn) {
	if !peerOK(conn) {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, err := readCommand(conn)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = writeFrame(conn, statusBad, nil)
		return
	}
	switch cmd {
	case cmdStop:
		applyStop()
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = writeFrame(conn, statusOK, nil)
	case cmdExport:
		applyExport(conn)
	default:
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = writeFrame(conn, statusBad, nil)
	}
}

func peerOK(conn *net.UnixConn) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var ucred *syscall.Ucred
	var gerr error
	cerr := raw.Control(func(fd uintptr) {
		ucred, gerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if cerr != nil || gerr != nil || ucred == nil {
		return false
	}
	return peerAllowed(ucred.Uid)
}

func peerAllowed(peer uint32) bool {
	return peer == 0
}

func shutdown() {
	listenMu.Lock()
	ln := current.ln
	fd := current.dirfd
	ino, dev := current.ino, current.dev
	done := current.done
	current = listenerState{dirfd: -1}
	listenMu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	if done != nil {
		<-done
	}
	if fd >= 0 {
		removeIfIno(fd, ino, dev)
		_ = syscall.Close(fd)
	}
}

// Client helpers used by tests live in the test file. Production callers use
// the socket path only.

func dialCommand(path string, cmd byte) (byte, []byte, error) {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	var req [5]byte
	copy(req[:4], "C4D1")
	req[4] = cmd
	if _, err := conn.Write(req[:]); err != nil {
		return 0, nil, err
	}
	return readFrame(conn)
}

func readFrame(r io.Reader) (byte, []byte, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	if string(hdr[:4]) != "C4D0" {
		return 0, nil, errFrame
	}
	n := binary.BigEndian.Uint32(hdr[5:9])
	if n > maxBytes {
		return 0, nil, errFrame
	}
	if n == 0 {
		return hdr[4], nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return hdr[4], buf, nil
}
