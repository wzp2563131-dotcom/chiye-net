package diag10443

import (
	"context"
	"net"
	"time"
)

// DialFunc is the REALITY handshake dial. The wrapper passes the same
// context, network and address through and returns the same conn and error.
// It does not choose a TFO or non-TFO branch.
type DialFunc func(context.Context, string, string) (net.Conn, error)

// SetConnIDFunc installs one process-local lookup. Only the uint32 and a
// presence bit can be stored. The function is not called while recording is off.
func SetConnIDFunc(fn func(context.Context) (uint32, bool)) {
	if fn == nil {
		return
	}
	idFn.Store(fn)
}

// WrapDialer returns the dial function installed in place of the REALITY
// handshake closure. While recording is off this is one atomic load.
func WrapDialer(inner DialFunc) DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if inner == nil {
			return nil, errBusy
		}
		if !enabled.Load() {
			return inner(ctx, network, addr)
		}
		return observe(ctx, network, addr, inner)
	}
}

func targetMatch(network, addr string) bool {
	if addr != targetAddr {
		return false
	}
	return network == "tcp" || network == "tcp4"
}

func observe(ctx context.Context, network, addr string, inner DialFunc) (net.Conn, error) {
	if !targetMatch(network, addr) {
		return inner(ctx, network, addr)
	}
	// Entry sample is before gate and reservation. It is not the pre-dial sample.
	entryMono := monoNs()
	entryEnum, entryHas, entryRemain := snapCtx(ctx)
	allow, definitive := gateDecision()
	if !allow {
		if definitive {
			disable(reasonGate)
		}
		return inner(ctx, network, addr)
	}
	attempt, ok := reserve()
	if !ok {
		return inner(ctx, network, addr)
	}
	finished := false
	defer func() {
		if !finished {
			releaseInflight()
		}
	}()
	// Pre sample is after gate/reservation and immediately before inner.
	preMono := monoNs()
	preEnum, preHas, preRemain := snapCtx(ctx)
	conn, err := inner(ctx, network, addr)
	retMono := monoNs()
	retEnum, retHas, retRemain := snapCtx(ctx)
	cls := safeClassify(err)
	id, idOK := loadID(ctx)
	finished = true
	var present uint8
	if idOK {
		present = 1
	} else {
		id = 0
	}
	commitOrDrop(sample{
		attempt:     attempt,
		connID:      id,
		connPresent: present,
		entryCtx:    entryEnum,
		entryHas:    entryHas,
		preCtx:      preEnum,
		preHas:      preHas,
		retCtx:      retEnum,
		retHas:      retHas,
		class:       cls.class,
		op:          cls.op,
		timeout:     cls.timeout,
		cause:       cls.cause,
		wrapper:     cls.wrapper,
		errno:       cls.errno,
		entryMono:   entryMono,
		preMono:     preMono,
		retMono:     retMono,
		entryRemain: entryRemain,
		preRemain:   preRemain,
		retRemain:   retRemain,
	}, err)
	return conn, err
}

func loadID(ctx context.Context) (id uint32, ok bool) {
	defer func() { _ = recover() }()
	if ctx == nil {
		return 0, false
	}
	v := idFn.Load()
	if v == nil {
		return 0, false
	}
	return v.(func(context.Context) (uint32, bool))(ctx)
}

func snapCtx(ctx context.Context) (enum, has uint8, remain int64) {
	if ctx == nil {
		return ctxUnknown, 0, 0
	}
	switch ctx.Err() {
	case nil:
		enum = ctxNil
	case context.Canceled:
		enum = ctxCanceled
	case context.DeadlineExceeded:
		enum = ctxDeadline
	default:
		enum = ctxUnknown
	}
	dl, ok := ctx.Deadline()
	if !ok {
		return enum, 0, 0
	}
	return enum, 1, time.Until(dl).Nanoseconds()
}
