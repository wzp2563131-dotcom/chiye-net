package diag10443

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"
)

var (
	errEntropy = errors.New("diag10443: entropy")
	errBusy    = errors.New("diag10443: busy")
)

func armBudget() error {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return errEntropy
	}
	token := binary.LittleEndian.Uint64(raw[:])
	wall := now()
	mu.Lock()
	defer mu.Unlock()
	if st.armed {
		return errBusy
	}
	st = state{
		armed:    true,
		token:    token,
		wall:     wall.UnixNano(),
		start:    wall,
		reserved: indexOverhead + exportScratch,
	}
	baseAt.Store(time.Now())
	return nil
}

func enableRecording() error {
	if err := armBudget(); err != nil {
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

func disarmBudget() {
	mu.Lock()
	st = state{}
	mu.Unlock()
	baseAt.Store(time.Time{})
	enabled.Store(false)
}

func reserve() (uint32, bool) {
	mu.Lock()
	defer mu.Unlock()
	if !st.armed || st.stopped || !enabled.Load() {
		return 0, false
	}
	if !now().Before(st.start.Add(maxAge)) {
		stopLocked(reasonTime)
		return 0, false
	}
	if st.errors >= maxErrors {
		stopLocked(reasonErrors)
		return 0, false
	}
	if st.reserved+recordSize > maxBytes {
		stopLocked(reasonSize)
		st.dropped++
		return 0, false
	}
	st.reserved += recordSize
	st.inflight++
	st.attempts++
	return st.attempts, true
}

func releaseInflight() {
	mu.Lock()
	if st.inflight > 0 {
		st.inflight--
	}
	if st.reserved >= recordSize {
		st.reserved -= recordSize
	}
	mu.Unlock()
}

func commitOrDrop(s sample, dialErr error) {
	mu.Lock()
	defer mu.Unlock()
	if st.inflight > 0 {
		st.inflight--
	}
	if st.reserved >= recordSize {
		st.reserved -= recordSize
	}
	if st.stopped || !enabled.Load() {
		if dialErr != nil {
			st.dropped++
		}
		return
	}
	if !now().Before(st.start.Add(maxAge)) {
		stopLocked(reasonTime)
		if dialErr != nil {
			st.dropped++
		}
		return
	}
	if dialErr == nil {
		return
	}
	if st.nrec >= maxErrors {
		stopLocked(reasonErrors)
		st.dropped++
		return
	}
	if st.reserved+recordSize > maxBytes {
		stopLocked(reasonSize)
		st.dropped++
		return
	}
	st.reserved += recordSize
	st.records[st.nrec] = s
	st.nrec++
	st.errors++
	if st.errors >= maxErrors {
		stopLocked(reasonErrors)
	}
}
