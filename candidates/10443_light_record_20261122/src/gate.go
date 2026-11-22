package diag10443

import (
	"io"
	"os"
	"strconv"
	"strings"
)

// gateDecision reads a cached or on-demand sample. definitive is false when
// another dial is already reading and this caller has no fresh sample: the
// caller skips the record and does not latch a stop. There is no background
// refresher. A passing cache may be up to gateTTL old, so this is not
// continuous protection.
func gateDecision() (allow, definitive bool) {
	if fn, ok := gatePause.Load().(func()); ok && fn != nil {
		fn()
	}
	nowT := now()
	gateMu.Lock()
	if !gateCache.at.IsZero() {
		age := nowT.Sub(gateCache.at)
		if age >= 0 && age < gateTTL {
			allow = gateCache.allow
			gateMu.Unlock()
			return allow, true
		}
	}
	if gateBusy {
		gateMu.Unlock()
		return false, false
	}
	gateBusy = true
	paths := gatePaths
	gateMu.Unlock()

	allow = readGate(paths)

	gateMu.Lock()
	gateCache.at = now()
	gateCache.allow = allow
	gateBusy = false
	gateMu.Unlock()
	return allow, true
}

func readGate(p gatePathSet) bool {
	load, ok := readScratch(p.load, 256)
	if !ok || !loadOK(string(load)) {
		return false
	}
	psi, ok := readScratch(p.psi, 1024)
	if !ok || !psiOK(string(psi)) {
		return false
	}
	mem, ok := readScratch(p.mem, 4096)
	if !ok || !memOK(string(mem)) {
		return false
	}
	return true
}

func readScratch(path string, limit int) ([]byte, bool) {
	dst := gateScratch()
	if dst == nil || limit > len(dst) {
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	n, err := f.Read(dst[:limit])
	if n <= 0 || (err != nil && err != io.EOF) {
		return nil, false
	}
	return dst[:n], true
}

func loadOK(text string) bool {
	field, _, _ := strings.Cut(text, " ")
	field = strings.TrimSpace(field)
	milli, ok := parseMilli(field)
	if !ok {
		return false
	}
	return milli < 750
}

func psiOK(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "some ") && line != "some" && !strings.HasPrefix(line, "some\t") {
			continue
		}
		const key = "avg10="
		i := strings.Index(line, key)
		if i < 0 {
			return false
		}
		rest := line[i+len(key):]
		rest, _, _ = strings.Cut(rest, " ")
		milli, ok := parseMilli(rest)
		if !ok {
			return false
		}
		return milli < 20000
	}
	return false
}

func memOK(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[2] != "kB" {
			return false
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return false
		}
		return kb >= 128*1024
	}
	return false
}

func parseMilli(s string) (int64, bool) {
	if s == "" || len(s) > 16 || s[0] == '-' || s[0] == '+' {
		return 0, false
	}
	whole, frac, ok := strings.Cut(s, ".")
	if strings.Contains(frac, ".") || whole == "" {
		return 0, false
	}
	w, err := strconv.ParseUint(whole, 10, 32)
	if err != nil {
		return 0, false
	}
	var f uint64
	if ok {
		if frac == "" || len(frac) > 6 {
			return 0, false
		}
		for _, c := range frac {
			if c < '0' || c > '9' {
				return 0, false
			}
		}
		padded := frac
		if len(padded) > 3 {
			padded = padded[:3]
		}
		for len(padded) < 3 {
			padded += "0"
		}
		f, err = strconv.ParseUint(padded, 10, 16)
		if err != nil {
			return 0, false
		}
	}
	return int64(w)*1000 + int64(f), true
}
