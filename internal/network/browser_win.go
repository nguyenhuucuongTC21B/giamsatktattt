//go:build windows

package network

import (
        "fmt"
        "io"
        "os"
        "path/filepath"
        "regexp"
        "strings"
)

// BrowserHistoryResult chứa thông tin lịch sử trình duyệt
type BrowserHistoryResult struct {
        BrowsersFound   []string
        TotalURLs       int
        SuspiciousURLs  []string
        SampleURLs      []string
}

// getBrowserHistory audit Chrome/Edge/Brave/CocCoc/Firefox
// Copy file History (đang khóa) → đọc binary → regex URL
// TIMEOUT 10 giây
func getBrowserHistory() BrowserHistoryResult {
        out := BrowserHistoryResult{}
        local := os.Getenv("LOCALAPPDATA")
        appdata := os.Getenv("APPDATA")
        if local == "" || appdata == "" {
                return out
        }

        chromiumPaths := []struct {
                Name string
                Path string
        }{
                {"Chrome", filepath.Join(local, `Google\Chrome\User Data\Default\History`)},
                {"Edge", filepath.Join(local, `Microsoft\Edge\User Data\Default\History`)},
                {"Brave", filepath.Join(local, `BraveSoftware\Brave-Browser\User Data\Default\History`)},
                {"CocCoc", filepath.Join(local, `CocCoc\Browser\User Data\Default\History`)},
        }

        urlRe := regexp.MustCompile(`https?://[a-zA-Z0-9.\-_/:%?=&#+~]{4,200}`)
        urlSet := map[string]bool{}

        for _, p := range chromiumPaths {
                if _, err := os.Stat(p.Path); err != nil {
                        continue
                }
                out.BrowsersFound = append(out.BrowsersFound, p.Name)
                tmp, err := copyLockedFile(p.Path)
                if err != nil {
                        continue
                }
                data, err := os.ReadFile(tmp)
                os.Remove(tmp)
                if err != nil {
                        continue
                }
                for _, m := range urlRe.FindAllString(string(data), -1) {
                        urlSet[m] = true
                }
        }

        // Firefox
        ffRoot := filepath.Join(appdata, `Mozilla\Firefox\Profiles`)
        if entries, err := os.ReadDir(ffRoot); err == nil {
                for _, e := range entries {
                        if !e.IsDir() {
                                continue
                        }
                        places := filepath.Join(ffRoot, e.Name(), "places.sqlite")
                        if _, err := os.Stat(places); err != nil {
                                continue
                        }
                        if !containsStr(out.BrowsersFound, "Firefox") {
                                out.BrowsersFound = append(out.BrowsersFound, "Firefox")
                        }
                        tmp, err := copyLockedFile(places)
                        if err != nil {
                                continue
                        }
                        data, err := os.ReadFile(tmp)
                        os.Remove(tmp)
                        if err != nil {
                                continue
                        }
                        for _, m := range urlRe.FindAllString(string(data), -1) {
                                urlSet[m] = true
                        }
                }
        }

        allURLs := make([]string, 0, len(urlSet))
        for u := range urlSet {
                allURLs = append(allURLs, u)
        }
        out.TotalURLs = len(allURLs)

        for i := 0; i < minInt(10, len(allURLs)); i++ {
                out.SampleURLs = append(out.SampleURLs, allURLs[i])
        }

        for _, u := range allURLs {
                lower := strings.ToLower(u)
                for _, bl := range blacklistedDomains {
                        if strings.Contains(lower, bl) {
                                out.SuspiciousURLs = append(out.SuspiciousURLs, u)
                                break
                        }
                }
        }

        return out
}

// copyLockedFile copy file đang bị khóa (Chrome/Edge đang chạy)
func copyLockedFile(src string) (string, error) {
        in, err := os.Open(src)
        if err != nil {
                return "", err
        }
        defer in.Close()

        tmp, err := os.CreateTemp("", "hist_*.db")
        if err != nil {
                return "", err
        }
        if _, err := io.Copy(tmp, in); err != nil {
                tmp.Close()
                os.Remove(tmp.Name())
                return "", err
        }
        tmp.Close()
        return tmp.Name(), nil
}

// formatBrowserHistorySummary trả về chuỗi tóm tắt
func formatBrowserHistorySummary(r BrowserHistoryResult) string {
        if len(r.BrowsersFound) == 0 {
                return "Không phát hiện trình duyệt phổ biến"
        }
        var sb strings.Builder
        sb.WriteString(strings.Join(r.BrowsersFound, ", "))
        sb.WriteString(fmt.Sprintf(" | %d URL", r.TotalURLs))
        if len(r.SuspiciousURLs) > 0 {
                sb.WriteString(fmt.Sprintf(" | ⚠ %d URL NGHI VẤN", len(r.SuspiciousURLs)))
                for i := 0; i < minInt(3, len(r.SuspiciousURLs)); i++ {
                        sb.WriteString("\n  • " + r.SuspiciousURLs[i])
                }
        }
        return sb.String()
}

func containsStr(s []string, v string) bool {
        for _, x := range s {
                if x == v {
                        return true
                }
        }
        return false
}

func minInt(a, b int) int {
        if a < b {
                return a
        }
        return b
}
