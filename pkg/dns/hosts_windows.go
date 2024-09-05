//go:build windows
// +build windows

package dns

import (
	"os"
	"path/filepath"
)

var hostsFile = filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
