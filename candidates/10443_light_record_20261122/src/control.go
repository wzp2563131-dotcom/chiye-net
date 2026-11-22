package diag10443

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

var errFrame = errors.New("diag10443: frame")

// Export is the single local reply on the control socket. It is not a file
// and there is no second interface.
func snapshotExport() []byte {
	mu.Lock()
	defer mu.Unlock()
	return encodeLocked()
}

func applyStop() {
	mu.Lock()
	enabled.Store(false)
	if !st.stopped {
		st.stopped = true
		st.reason = reasonManual
	}
	st.manual = true
	mu.Unlock()
}

func boundWrite(w io.Writer) {
	type deadliner interface{ SetWriteDeadline(time.Time) error }
	if d, ok := w.(deadliner); ok {
		_ = d.SetWriteDeadline(time.Now().Add(2 * time.Second))
	}
}

func applyExport(w io.Writer) {
	allow, definitive := gateDecision()
	if !allow {
		boundWrite(w)
		if definitive {
			disable(reasonGate)
			_ = writeFrame(w, statusGate, nil)
		} else {
			_ = writeFrame(w, statusBusy, nil)
		}
		return
	}
	mu.Lock()
	if !st.armed {
		mu.Unlock()
		boundWrite(w)
		_ = writeFrame(w, statusBad, nil)
		return
	}
	if st.exportBusy {
		mu.Unlock()
		boundWrite(w)
		_ = writeFrame(w, statusBusy, nil)
		return
	}
	if st.exported {
		mu.Unlock()
		boundWrite(w)
		_ = writeFrame(w, statusAlready, nil)
		return
	}
	st.exportBusy = true
	frame := encodeFrameLocked()
	mu.Unlock()

	if fn, ok := exportWait.Load().(func()); ok && fn != nil {
		fn()
	}
	boundWrite(w)
	_, err := w.Write(frame)
	mu.Lock()
	if err == nil {
		st.exported = true
	}
	st.exportBusy = false
	mu.Unlock()
}

func writeFrame(w io.Writer, status byte, payload []byte) error {
	if payload == nil {
		payload = []byte{}
	}
	if len(payload) > maxBytes {
		return errFrame
	}
	buf := make([]byte, 9+len(payload))
	copy(buf[:4], "C4D0")
	buf[4] = status
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(payload)))
	copy(buf[9:], payload)
	_, err := w.Write(buf)
	return err
}

func readCommand(r io.Reader) (byte, error) {
	var req [5]byte
	if _, err := io.ReadFull(r, req[:]); err != nil {
		return 0, err
	}
	if string(req[:4]) != "C4D1" {
		return 0, errFrame
	}
	return req[4], nil
}
