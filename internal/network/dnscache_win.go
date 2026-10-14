//go:build windows

package network

import (
        "bytes"
        "regexp"
        "strings"
        "time"
)

// DNSCacheResult chứa thông tin DNS cache và domain nghi vấn
type DNSCacheResult struct {
        TotalEntries        int
        SuspiciousDomains   []string
        CommercialDomains   []string
        AllDomains          []string
}

// Blacklist domain/từ khóa nhận diện link lạ
var blacklistedDomains = []string{
        "malware", "crack", "keygen", "torproject", ".onion",
        "pastebin.com", "ngrok.io", "spyware", "phishing",
        "bit.ly", "tinyurl.com", "free-download", "hack",
        "warez", "pirate", "torrent", "mega.nz", "mediafire",
}

// getDNSCache đọc ipconfig /displaydns và trích xuất domain đã cache
// TIMEOUT 10 giây để tránh treo
func getDNSCache() DNSCacheResult {
        out := DNSCacheResult{}

        cmd := hideWindowCmd("ipconfig", "/displaydns")
        var stdout bytes.Buffer
        cmd.Stdout = &stdout

        // Timeout 10 giây
        done := make(chan error, 1)
        go func() { done <- cmd.Run() }()
        select {
        case <-done:
        case <-time.After(10 * time.Second):
                if cmd.Process != nil {
                        cmd.Process.Kill()
                }
                return out
        }

        dnsOutput := stdout.String()
        dnsRe := regexp.MustCompile(`(?i)Record Name\s*\.\s*\.\s*:\s*(\S+)`)
        domainSet := map[string]bool{}
        for _, m := range dnsRe.FindAllStringSubmatch(dnsOutput, -1) {
                if len(m) > 1 {
                        domain := strings.TrimSpace(m[1])
                        domainSet[domain] = true
                }
        }

        out.AllDomains = make([]string, 0, len(domainSet))
        for d := range domainSet {
                out.AllDomains = append(out.AllDomains, d)
        }
        out.TotalEntries = len(out.AllDomains)

        commercialRe := regexp.MustCompile(`(?i)(google|facebook|github|youtube|microsoft|cloudflare|amazon|netflix|spotify|tiktok|zalo|vng)\.`)
        for _, d := range out.AllDomains {
                lower := strings.ToLower(d)
                isSuspicious := false
                for _, bl := range blacklistedDomains {
                        if strings.Contains(lower, bl) {
                                out.SuspiciousDomains = append(out.SuspiciousDomains, d)
                                isSuspicious = true
                                break
                        }
                }
                if !isSuspicious && commercialRe.MatchString(lower) {
                        out.CommercialDomains = append(out.CommercialDomains, d)
                }
        }

        return out
}

// formatDNSCacheSummary trả về chuỗi tóm tắt cho frontend
func formatDNSCacheSummary(r DNSCacheResult) string {
        if r.TotalEntries == 0 {
                return "DNS cache trống (có thể đã bị xóa)"
        }
        var sb strings.Builder
        sb.WriteString("Tổng " + itoa(r.TotalEntries) + " domain đã cache")
        if len(r.SuspiciousDomains) > 0 {
                sb.WriteString(" | ⚠ " + itoa(len(r.SuspiciousDomains)) + " domain NGHI VẤN: ")
                n := len(r.SuspiciousDomains)
                if n > 5 {
                        n = 5
                }
                sb.WriteString(strings.Join(r.SuspiciousDomains[:n], ", "))
        }
        if len(r.CommercialDomains) > 0 {
                sb.WriteString(" | " + itoa(len(r.CommercialDomains)) + " domain quốc tế (đã từng vào Internet)")
        }
        return sb.String()
}
