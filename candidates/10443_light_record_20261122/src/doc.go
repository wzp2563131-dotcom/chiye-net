// Package diag10443 is a frozen diagnostic candidate for one REALITY
// handshake dial target. It is not a production fix and it does not claim a
// root cause for 10443 or 8443.
//
// approvedSwitch is false. The process does not listen or record until a
// future deployment order changes that constant and rebuilds. There is no
// runtime enable and no renewal command.
//
// The observation point is the REALITY DialContext closure, before utls
// flattens the error. The same closure is used for both the TFO and non-TFO
// dialer branches. The production branch is unknown and is not selected here.
// A TFO slow-open that returns a connection before the TCP handshake does not
// surface a later connect error at this hook; this package does not add a
// second hook on Write.
package diag10443
