//go:build windows

package license

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ComponentVersion chứa phiên bản phần mềm + CVE match
type ComponentVersion struct {
	Name    string // "Google Chrome", "Microsoft Edge", "Java", "OpenSSL"
	Version string
	CVEs    []CVEInfo
}

// CVEInfo chứa thông tin CVE
type CVEInfo struct {
	ID       string
	Severity string
	MaxVer   string
	Desc     string
}

// CSDL CVE tĩnh cho Chrome/Edge/Java/OpenSSL
var staticCVEDb = []CVEInfo{
	{"CVE-2024-0519", "CRITICAL", "120.0.6099.130", "Out-of-bounds memory access in V8 (RCE via Web)"},
	{"CVE-2024-0800", "HIGH", "121.0.6167.85", "Object lifecycle issue in V8"},
	{"CVE-2024-0518", "HIGH", "120.0.6099.130", "Type confusion in V8"},
	{"CVE-2024-0517", "HIGH", "120.0.6099.130", "Type confusion in V8"},
	{"CVE-2022-3602", "HIGH", "3.0.7", "X.509 Email Address Buffer Overflow (RCE)"},
	{"CVE-2022-3786", "HIGH", "1.1.1s", "X.509 Email Address Buffer Overflow"},
	{"CVE-2022-21449", "HIGH", "17.0.5", "ECDSA Signature Verification Bypass (Psychic Signatures)"},
	{"CVE-2022-21449", "HIGH", "1.8.0_351", "ECDSA Signature Verification Bypass"},
}

// scanComponentVersions lấy phiên bản Chrome/Edge/Java/OpenSSL + đối chiếu CVE
// Trả về các LicenseRecord bổ sung cho Bảng I
func scanComponentVersions() []LicenseRecord {
	var records []LicenseRecord

	// 1. Google Chrome
	if v := getChromeVersion(); v != "" {
		rec := LicenseRecord{
			SoftwareName:     "Google Chrome",
			Version:          v,
			ProductID:        "",
			LicensingChannel: "Retail (Free)",
			BIOSOEMKey:       "",
			CrackTool:        "",
			CrackPath:        "",
			Legal:            true,
		}
		cves := matchComponentCVE("chrome", v)
		if len(cves) > 0 {
			rec.CrackTool = formatCVEReport(cves)
			rec.Legal = false // có CVE nghiêm trọng → đánh dấu cần cập nhật
		}
		records = append(records, rec)
	}

	// 2. Microsoft Edge
	if v := getEdgeVersion(); v != "" {
		rec := LicenseRecord{
			SoftwareName:     "Microsoft Edge",
			Version:          v,
			LicensingChannel: "Retail (Free)",
			Legal:            true,
		}
		cves := matchComponentCVE("msedge", v)
		if len(cves) > 0 {
			rec.CrackTool = formatCVEReport(cves)
			rec.Legal = false
		}
		records = append(records, rec)
	}

	// 3. Java Runtime
	if v := getJavaVersion(); v != "" {
		rec := LicenseRecord{
			SoftwareName:     "Java Runtime Environment",
			Version:          v,
			LicensingChannel: "Unknown",
			Legal:            true,
		}
		cves := matchComponentCVE("java", v)
		if len(cves) > 0 {
			rec.CrackTool = formatCVEReport(cves)
			rec.Legal = false
		}
		records = append(records, rec)
	}

	// 4. OpenSSL
	if v := getOpenSSLVersion(); v != "" {
		rec := LicenseRecord{
			SoftwareName:     "OpenSSL",
			Version:          v,
			LicensingChannel: "Open Source",
			Legal:            true,
		}
		cves := matchComponentCVE("openssl", v)
		if len(cves) > 0 {
			rec.CrackTool = formatCVEReport(cves)
			rec.Legal = false
		}
		records = append(records, rec)
	}

	return records
}

// getChromeVersion lấy phiên bản Chrome từ registry hoặc file
func getChromeVersion() string {
	out := runCMD("reg", "query",
		`HKCU\Software\Google\Chrome\BLBeacon`, "/v", "version")
	if m := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`).FindStringSubmatch(out); m != nil {
		return m[1]
	}
	p := filepath.Join(os.Getenv("ProgramFiles"),
		`Google\Chrome\Application\chrome.exe`)
	if _, err := os.Stat(p); err == nil {
		v := runCMD("powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`(Get-Item '%s').VersionInfo.ProductVersion`, p))
		if m := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`).FindStringSubmatch(v); m != nil {
			return m[1]
		}
	}
	return ""
}

// getEdgeVersion lấy phiên bản Edge
func getEdgeVersion() string {
	pf86 := os.Getenv("ProgramFiles(x86)")
	if pf86 == "" {
		pf86 = `C:\Program Files (x86)`
	}
	p := filepath.Join(pf86, `Microsoft\Edge\Application\msedge.exe`)
	if _, err := os.Stat(p); err == nil {
		v := runCMD("powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`(Get-Item '%s').VersionInfo.ProductVersion`, p))
		if m := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`).FindStringSubmatch(v); m != nil {
			return m[1]
		}
	}
	return ""
}

// getJavaVersion lấy phiên bản Java
func getJavaVersion() string {
	out := runCMD("java", "-version")
	if m := regexp.MustCompile(`"(\d+\.\d+\.\d+[_\.]\d+)"`).FindStringSubmatch(out); m != nil {
		return strings.ReplaceAll(m[1], "_", ".")
	}
	if m := regexp.MustCompile(`version "([^"]+)"`).FindStringSubmatch(out); m != nil {
		return strings.ReplaceAll(m[1], "_", ".")
	}
	return ""
}

// getOpenSSLVersion lấy phiên bản OpenSSL
func getOpenSSLVersion() string {
	out := runCMD("openssl", "version")
	if m := regexp.MustCompile(`OpenSSL (\d+\.\d+\.\d+\w*)`).FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// matchComponentCVE đối chiếu phiên bản với CSDL CVE tĩnh
func matchComponentCVE(app, version string) []CVEInfo {
	var matches []CVEInfo
	// Đơn giản hoá: chỉ check app name chứa keyword
	appLower := lower(app)
	for _, cve := range staticCVEDb {
		// Mỗi CVE có field "MaxVer" riêng, không có app field
		// Nên cần check theo app name
		if isCVEForApp(cve, appLower) {
			if compareVersion(version, cve.MaxVer) <= 0 {
				matches = append(matches, cve)
			}
		}
	}
	return matches
}

// isCVEForApp kiểm tra CVE có dành cho app này không
// (đơn giản hoá - dựa vào MaxVer format)
func isCVEForApp(cve CVEInfo, app string) bool {
	// CVE-2024-0519, 0518, 0517, 0800 → Chrome/Edge (V8 engine)
	chromeCVEs := []string{"CVE-2024-0519", "CVE-2024-0800", "CVE-2024-0518", "CVE-2024-0517"}
	for _, id := range chromeCVEs {
		if cve.ID == id && (app == "chrome" || app == "msedge") {
			return true
		}
	}
	// CVE-2022-3602 → OpenSSL 3.x
	if cve.ID == "CVE-2022-3602" && app == "openssl" {
		return true
	}
	// CVE-2022-3786 → OpenSSL 1.1.x
	if cve.ID == "CVE-2022-3786" && app == "openssl" {
		return true
	}
	// CVE-2022-21449 → Java
	if cve.ID == "CVE-2022-21449" && app == "java" {
		return true
	}
	return false
}

// formatCVEReport trả về chuỗi mô tả CVE cho frontend
func formatCVEReport(cves []CVEInfo) string {
	var sb strings.Builder
	for i, cve := range cves {
		if i > 0 {
			sb.WriteString(" | ")
		}
		sb.WriteString(cve.ID + " [" + cve.Severity + "] (≤" + cve.MaxVer + ") - " + cve.Desc)
	}
	return sb.String()
}

// runCMD chạy command và trả về output
func runCMD(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	_ = cmd.Run()
	return out.String()
}

// compareVersion so sánh 2 phiên bản dạng 1.2.3.4
// Trả về: -1 nếu v1 < v2, 0 nếu bằng, 1 nếu v1 > v2
func compareVersion(v1, v2 string) int {
	a := parseVersion(v1)
	b := parseVersion(v2)
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// parseVersion tách chuỗi version thành []int
func parseVersion(v string) []int {
	re := regexp.MustCompile(`\d+`)
	parts := re.FindAllString(v, -1)
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}

// lower helper (đã có trong scanner.go nhưng để fallback nếu chưa import)
func lower_local(s string) string {
	return strings.ToLower(s)
}
