package diag10443

import (
	"encoding/binary"
	"errors"
)

var errSchema = errors.New("diag10443: schema")

func gateScratch() []byte {
	mu.Lock()
	arena := st.arena
	mu.Unlock()
	if len(arena) < indexOverhead+exportFrameSize+gateScratchSize {
		return nil
	}
	off := indexOverhead + exportFrameSize
	return arena[off : off+gateScratchSize]
}

func retainedSlot(i int) []byte {
	off := indexOverhead + exportFrameSize + gateScratchSize + i*recordSize
	return st.arena[off : off+recordSize]
}

func encodeFrameLocked() []byte {
	frame := st.arena[indexOverhead : indexOverhead+exportFrameSize]
	for i := range frame {
		frame[i] = 0
	}
	n := st.nrec
	if n < 0 {
		n = 0
	}
	if n > maxErrors {
		n = maxErrors
	}
	payloadLen := headerSize + n*recordSize
	payload := frame[9 : 9+payloadLen]
	copy(payload[0:4], "C443")
	payload[4] = schemaVersion
	payload[5] = flagByte()
	payload[6] = st.reason
	payload[7] = byte(n)
	binary.LittleEndian.PutUint64(payload[8:16], st.token)
	binary.LittleEndian.PutUint64(payload[16:24], uint64(st.wall))
	binary.LittleEndian.PutUint32(payload[24:28], st.dropped)
	binary.LittleEndian.PutUint32(payload[28:32], uint32(clampReserved(st.reserved)))
	binary.LittleEndian.PutUint32(payload[32:36], uint32(clampNonNeg(st.inflight)))
	for i := 0; i < n; i++ {
		copy(payload[headerSize+i*recordSize:headerSize+(i+1)*recordSize], retainedSlot(i))
	}
	copy(frame[0:4], "C4D0")
	frame[4] = statusOK
	binary.BigEndian.PutUint32(frame[5:9], uint32(payloadLen))
	return frame[:9+payloadLen]
}

func encodeLocked() []byte {
	frame := encodeFrameLocked()
	n := int(binary.BigEndian.Uint32(frame[5:9]))
	out := make([]byte, n)
	copy(out, frame[9:9+n])
	return out
}

func flagByte() uint8 {
	var f uint8
	if enabled.Load() {
		f |= flagEnabled
	}
	if st.stopped {
		f |= flagStopped
	}
	if st.exported {
		f |= flagExported
	}
	if st.manual {
		f |= flagManual
	}
	if approvedSwitch {
		f |= flagSwitch
	}
	return f
}

func clampReserved(v int) int {
	if v < 0 {
		return 0
	}
	if v > maxBytes {
		return maxBytes
	}
	return v
}

func clampNonNeg(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

func putRecord(b []byte, s *sample) {
	for i := range b {
		b[i] = 0
	}
	binary.LittleEndian.PutUint32(b[0:4], s.attempt)
	b[4] = s.connPresent
	b[5] = s.entryCtx
	b[6] = s.entryHas
	b[7] = s.preCtx
	b[8] = s.preHas
	b[9] = s.retCtx
	b[10] = s.retHas
	b[11] = s.class
	b[12] = s.op
	b[13] = s.timeout
	b[14] = s.cause
	b[15] = s.wrapper
	binary.LittleEndian.PutUint32(b[16:20], s.connID)
	binary.LittleEndian.PutUint32(b[20:24], uint32(s.errno))
	binary.LittleEndian.PutUint64(b[24:32], uint64(s.entryMono))
	binary.LittleEndian.PutUint64(b[32:40], uint64(s.preMono))
	binary.LittleEndian.PutUint64(b[40:48], uint64(s.retMono))
	binary.LittleEndian.PutUint64(b[48:56], uint64(s.entryRemain))
	binary.LittleEndian.PutUint64(b[56:64], uint64(s.preRemain))
	binary.LittleEndian.PutUint64(b[64:72], uint64(s.retRemain))
}

func decodeExport(b []byte) (flags, reason byte, dropped uint32, records []sample, err error) {
	if len(b) < headerSize || len(b) > maxBytes {
		return 0, 0, 0, nil, errSchema
	}
	if string(b[0:4]) != "C443" || b[4] != schemaVersion {
		return 0, 0, 0, nil, errSchema
	}
	flags = b[5]
	reason = b[6]
	n := int(b[7])
	if n > maxErrors || len(b) != headerSize+n*recordSize {
		return 0, 0, 0, nil, errSchema
	}
	if b[36] != 0 || b[37] != 0 || b[38] != 0 || b[39] != 0 {
		return 0, 0, 0, nil, errSchema
	}
	if reason > reasonManual {
		return 0, 0, 0, nil, errSchema
	}
	dropped = binary.LittleEndian.Uint32(b[24:28])
	records = make([]sample, n)
	for i := 0; i < n; i++ {
		rec, derr := takeRecord(b[headerSize+i*recordSize : headerSize+(i+1)*recordSize])
		if derr != nil {
			return 0, 0, 0, nil, derr
		}
		records[i] = rec
	}
	return flags, reason, dropped, records, nil
}

func takeRecord(b []byte) (sample, error) {
	if len(b) != recordSize {
		return sample{}, errSchema
	}
	for _, pad := range b[72:80] {
		if pad != 0 {
			return sample{}, errSchema
		}
	}
	s := sample{
		attempt:     binary.LittleEndian.Uint32(b[0:4]),
		connPresent: b[4],
		entryCtx:    b[5],
		entryHas:    b[6],
		preCtx:      b[7],
		preHas:      b[8],
		retCtx:      b[9],
		retHas:      b[10],
		class:       b[11],
		op:          b[12],
		timeout:     b[13],
		cause:       b[14],
		wrapper:     b[15],
		connID:      binary.LittleEndian.Uint32(b[16:20]),
		errno:       int32(binary.LittleEndian.Uint32(b[20:24])),
		entryMono:   int64(binary.LittleEndian.Uint64(b[24:32])),
		preMono:     int64(binary.LittleEndian.Uint64(b[32:40])),
		retMono:     int64(binary.LittleEndian.Uint64(b[40:48])),
		entryRemain: int64(binary.LittleEndian.Uint64(b[48:56])),
		preRemain:   int64(binary.LittleEndian.Uint64(b[56:64])),
		retRemain:   int64(binary.LittleEndian.Uint64(b[64:72])),
	}
	if s.connPresent > 1 || s.entryHas > 1 || s.preHas > 1 || s.retHas > 1 || s.timeout > 1 {
		return sample{}, errSchema
	}
	if s.entryCtx > ctxUnknown || s.preCtx > ctxUnknown || s.retCtx > ctxUnknown || s.class > classUnknown || s.cause > classUnknown {
		return sample{}, errSchema
	}
	if s.op > opOther || s.wrapper > wrapperSyscall {
		return sample{}, errSchema
	}
	if s.class != classErrno && s.errno != 0 {
		return sample{}, errSchema
	}
	if s.connPresent == 0 && s.connID != 0 {
		return sample{}, errSchema
	}
	if s.entryHas == 0 && s.entryRemain != 0 {
		return sample{}, errSchema
	}
	if s.preHas == 0 && s.preRemain != 0 {
		return sample{}, errSchema
	}
	if s.retHas == 0 && s.retRemain != 0 {
		return sample{}, errSchema
	}
	return s, nil
}
