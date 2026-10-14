// Package secretscan chứa logic rà quét sâu văn bản Word/PDF
// phát hiện nội dung chứa từ khóa "Mật", "Bí mật", "Tuyệt mật"
//
// API chính: ScanSecretDocs() -> []SecretDocRecord (Bảng VI)
package secretscan

// SecretDocRecord tương ứng BẢNG VI trong đặc tả đầu ra.
type SecretDocRecord struct {
	FilePath       string `json:"file_path"`         // Đường dẫn đầy đủ
	FileName       string `json:"file_name"`         // Tên file
	FileType       string `json:"file_type"`         // .docx | .doc | .pdf | .xlsx | .pptx
	FileSize       int64  `json:"file_size"`         // Kích thước (bytes)
	ModifiedDate   string `json:"modified_date"`     // Ngày sửa đổi
	Classification string `json:"classification"`    // MẬT | BÍ MẬT | TUYỆT MẬT | NGHI VẤN
	MatchedKeywords string `json:"matched_keywords"` // Các từ khóa phát hiện
	KeywordCount   int    `json:"keyword_count"`     // Số lần xuất hiện
	Snippet        string `json:"snippet"`           // Đoạn văn bản xung quanh từ khóa
	Location       string `json:"location"`          // Desktop | Documents | Downloads | USB
	DangerLevel    string `json:"danger_level"`      // CRITICAL | HIGH | MEDIUM
}

// SecretScanResult chứa kết quả tổng hợp
type SecretScanResult struct {
	Records       []SecretDocRecord
	TotalFiles    int
	TotalMatches  int
	CriticalCount int
	HighCount     int
	Summary       string
}
