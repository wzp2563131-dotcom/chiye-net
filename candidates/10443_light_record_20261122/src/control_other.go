//go:build !linux

package diag10443

import "errors"

var errUnsupported = errors.New("diag10443: unsupported")

func start(string) error { return errUnsupported }

func shutdown() {}
