//go:build !windows

package license

type ComponentVersion struct {
	Name    string
	Version string
	CVEs    []CVEInfo
}

type CVEInfo struct {
	ID       string
	Severity string
	MaxVer   string
	Desc     string
}

func scanComponentVersions() []LicenseRecord { return nil }
