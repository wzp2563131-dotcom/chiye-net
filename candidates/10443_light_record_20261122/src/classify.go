package diag10443

import (
	"context"
	"net"
	"os"
	"syscall"
)

func safeClassify(err error) (c classified) {
	c.class = classUnknown
	defer func() {
		if recover() != nil {
			c = classified{class: classUnknown}
		}
	}()
	if err == nil {
		return classified{class: classNone}
	}
	return classify(err)
}

func classify(err error) classified {
	c := classified{class: classUnknown}
	c.wrapper, c.op = topShape(err)
	c.class, c.errno = walk(err)
	if c.wrapper != wrapperNone {
		if inner := unwrapOne(err); inner != nil {
			c.cause, _ = walk(inner)
		}
	}
	if timeoutBit(err) {
		c.timeout = 1
	}
	return c
}

func topShape(err error) (wrapper, op uint8) {
	switch e := err.(type) {
	case *net.OpError:
		op = opOther
		if len(e.Op) == 4 && e.Op == "dial" {
			op = opDial
		}
		return wrapperOpError, op
	case *os.SyscallError:
		return wrapperSyscall, opNone
	default:
		return wrapperNone, opNone
	}
}

func walk(err error) (uint8, int32) {
	for i := 0; i < maxUnwrap && err != nil; i++ {
		switch err {
		case context.Canceled:
			return classCanceled, 0
		case context.DeadlineExceeded:
			return classDeadline, 0
		}
		if errno, ok := err.(syscall.Errno); ok {
			if errnoAllowed(errno) {
				return classErrno, int32(errno)
			}
			return classUnknown, 0
		}
		if _, isOp := err.(*net.OpError); !isOp {
			if _, isSys := err.(*os.SyscallError); !isSys {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					return classTimeout, 0
				}
			}
		}
		next := unwrapOne(err)
		if next == nil || next == err {
			return classUnknown, 0
		}
		err = next
	}
	return classUnknown, 0
}

func unwrapOne(err error) error {
	switch e := err.(type) {
	case *net.OpError:
		return e.Err
	case *os.SyscallError:
		return e.Err
	default:
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return nil
		}
		return u.Unwrap()
	}
}

func timeoutBit(err error) bool {
	for i := 0; i < maxUnwrap && err != nil; i++ {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return true
		}
		next := unwrapOne(err)
		if next == nil || next == err {
			return false
		}
		err = next
	}
	return false
}

func errnoAllowed(e syscall.Errno) bool {
	switch e {
	case syscall.ECONNREFUSED,
		syscall.ECONNRESET,
		syscall.ETIMEDOUT,
		syscall.EHOSTUNREACH,
		syscall.ENETUNREACH,
		syscall.EPIPE,
		syscall.ECONNABORTED,
		syscall.EAGAIN:
		return true
	default:
		return false
	}
}
