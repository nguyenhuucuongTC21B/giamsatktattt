//go:build !windows

package network

type DNSCacheResult struct {
	TotalEntries      int
	SuspiciousDomains []string
	CommercialDomains []string
	AllDomains        []string
}

func getDNSCache() DNSCacheResult { return DNSCacheResult{} }
func formatDNSCacheSummary(r DNSCacheResult) string { return "DNS cache chỉ khả dụng trên Windows" }

type BrowserHistoryResult struct {
	BrowsersFound   []string
	TotalURLs       int
	SuspiciousURLs  []string
	SampleURLs      []string
}

func getBrowserHistory() BrowserHistoryResult { return BrowserHistoryResult{} }
func formatBrowserHistorySummary(r BrowserHistoryResult) string { return "Browser history chỉ khả dụng trên Windows" }

type LANConfigResult struct {
	SMBv1Enabled  bool
	SMBv1Status   string
	LLMNRDisabled bool
	LLMNRStatus   string
	NetBIOSStatus string
	Summary       string
}

func getLANConfig() LANConfigResult { return LANConfigResult{} }

type DocumentLinksResult struct {
	TotalDocs       int
	TotalLinks      int
	SuspiciousLinks int
	SuspiciousURLs  []string
	Summary         string
}

func scanDocumentsForLinks() DocumentLinksResult { return DocumentLinksResult{} }
