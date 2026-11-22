package diag10443

import (
	"sync"
	"sync/atomic"
	"time"
)

// approvedSwitch stays false in this frozen candidate. A later order may
// change it to true and rebuild. No command turns recording on.
const approvedSwitch = false

const (
	prodDir  = "/run/chiye-net"
	sockName = "10443-diag.sock"

	targetAddr = "127.0.0.1:10443"

	maxErrors     = 10
	maxBytes      = 64 * 1024
	maxAge        = 30 * time.Minute
	indexOverhead = 256
	exportScratch = 1024
	recordSize    = 64
	headerSize    = 40
	schemaVersion = 1
	maxUnwrap     = 4
	gateTTL       = time.Second
)

const (
	reasonNone   uint8 = 0
	reasonErrors uint8 = 1
	reasonSize   uint8 = 2
	reasonTime   uint8 = 3
	reasonGate   uint8 = 4
	reasonManual uint8 = 5
)

const (
	ctxNil      uint8 = 0
	ctxCanceled uint8 = 1
	ctxDeadline uint8 = 2
	ctxUnknown  uint8 = 3
)

const (
	classNone     uint8 = 0
	classCanceled uint8 = 1
	classDeadline uint8 = 2
	classTimeout  uint8 = 3
	classErrno    uint8 = 4
	classUnknown  uint8 = 5
)

const (
	wrapperNone    uint8 = 0
	wrapperOpError uint8 = 1
	wrapperSyscall uint8 = 2
)

const (
	opNone  uint8 = 0
	opDial  uint8 = 1
	opOther uint8 = 2
)

const (
	flagEnabled  uint8 = 1 << 0
	flagStopped  uint8 = 1 << 1
	flagExported uint8 = 1 << 2
	flagManual   uint8 = 1 << 3
	flagSwitch   uint8 = 1 << 4
)

const (
	cmdStop   byte = 1
	cmdExport byte = 2

	statusOK      byte = 0
	statusBad     byte = 1
	statusAlready byte = 2
	statusGate    byte = 3
	statusBusy    byte = 4
)

type sample struct {
	attempt     uint32
	connID      uint32
	connPresent uint8
	entryCtx    uint8
	entryHas    uint8
	retCtx      uint8
	retHas      uint8
	class       uint8
	op          uint8
	timeout     uint8
	cause       uint8
	wrapper     uint8
	errno       int32
	entryMono   int64
	preMono     int64
	retMono     int64
	entryRemain int64
	retRemain   int64
}

type classified struct {
	class   uint8
	errno   int32
	wrapper uint8
	op      uint8
	timeout uint8
	cause   uint8
}

type state struct {
	armed      bool
	stopped    bool
	manual     bool
	exported   bool
	exportBusy bool
	reason     uint8
	errors     int
	reserved   int
	inflight   int
	nrec       int
	attempts   uint32
	dropped    uint32
	token      uint64
	wall       int64
	start      time.Time
	records    [maxErrors]sample
}

type gateSnap struct {
	at    time.Time
	allow bool
}

type gatePathSet struct {
	load string
	psi  string
	mem  string
}

var (
	enabled atomic.Bool

	mu sync.Mutex
	st state

	baseAt atomic.Value // time.Time

	nowFn atomic.Value // func() time.Time

	gateMu    sync.Mutex
	gateCache gateSnap
	gateBusy  bool
	gatePaths = gatePathSet{
		load: "/proc/loadavg",
		psi:  "/proc/pressure/cpu",
		mem:  "/proc/meminfo",
	}

	idFn atomic.Value // func(context.Context) (uint32, bool)

	exportWait atomic.Value // func()
)

func init() {
	if indexOverhead+exportScratch+recordSize > maxBytes {
		panic("diag10443: budget constants exceed 64KiB")
	}
	nowFn.Store(time.Now)
	if approvedSwitch {
		_ = start(prodDir)
	}
}

func now() time.Time {
	return nowFn.Load().(func() time.Time)()
}

func setNow(fn func() time.Time) {
	if fn == nil {
		nowFn.Store(time.Now)
		return
	}
	nowFn.Store(fn)
}

func monoNs() int64 {
	v := baseAt.Load()
	if v == nil {
		return 0
	}
	base := v.(time.Time)
	if base.IsZero() {
		return 0
	}
	return time.Since(base).Nanoseconds()
}

func stopLocked(reason uint8) {
	enabled.Store(false)
	if !st.stopped {
		st.stopped = true
		st.reason = reason
	}
}

func disable(reason uint8) {
	mu.Lock()
	stopLocked(reason)
	mu.Unlock()
}

func maxInflight() int {
	return (maxBytes - indexOverhead - exportScratch) / recordSize
}
