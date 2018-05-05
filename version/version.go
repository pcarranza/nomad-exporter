package version

import "fmt"

// Version is the version, duh
var Version string

// Date is the build date
var Date string

// Commit is the commit that was built
var Commit string

// GetVersion returns the binary version
func GetVersion() string {
	return fmt.Sprintf("nomad-exporter Version: %s Commit: %s Date: %s", Version, Commit, Date)
}
