package diag10443

import "context"

func resetForTest() {
	shutdown()
	disarmBudget()
	setNow(nil)
	idFn.Store(func(context.Context) (uint32, bool) { return 0, false })
	exportWait.Store(func() {})
	gateMu.Lock()
	gateCache = gateSnap{}
	gateBusy = false
	gatePaths = gatePathSet{
		load: "/proc/loadavg",
		psi:  "/proc/pressure/cpu",
		mem:  "/proc/meminfo",
	}
	gateMu.Unlock()
}
