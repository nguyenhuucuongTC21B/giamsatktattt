package secretscan

// SecretDocRecord tương ứng BẢNG VI
type SecretDocRecord struct {
	FilePath        string `json:"file_path"`
	FileName        string `json:"file_name"`
	FileType        string `json:"file_type"`
	FileSize        int64  `json:"file_size"`
	ModifiedDate    string `json:"modified_date"`
	Classification  string `json:"classification"`
	MatchedKeywords string `json:"matched_keywords"`
	KeywordCount    int    `json:"keyword_count"`
	Snippet         string `json:"snippet"`
	Location        string `json:"location"`
	DangerLevel     string `json:"danger_level"`
}

// ScannedDir chứa thông tin thư mục đã quét
type ScannedDir struct {
	Path       string `json:"path"`
	FileCount  int    `json:"file_count"`
	MatchCount int    `json:"match_count"`
}

// SecretScanResult chứa kết quả tổng hợp
type SecretScanResult struct {
	Records       []SecretDocRecord
	ScannedDirs   []ScannedDir
	TotalFiles    int
	TotalMatches  int
	CriticalCount int
	HighCount     int
	Summary       string
	LogFilePath   string
}
