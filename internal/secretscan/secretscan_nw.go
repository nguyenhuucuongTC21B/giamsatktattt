//go:build !windows

package secretscan

// ScanSecretDocs stub cho non-Windows (dev/demo)
func ScanSecretDocs() SecretScanResult {
	return SecretScanResult{
		Records: []SecretDocRecord{
			{
				FilePath:        "C:\\Users\\Admin\\Documents\\Bao-cao-mat-Q4.docx",
				FileName:        "Bao-cao-mat-Q4.docx",
				FileType:        ".docx",
				FileSize:        145820,
				ModifiedDate:    "2026-08-15T14:30:00Z",
				Classification:  "MẬT",
				MatchedKeywords: "mật, tài liệu mật, ban cơ yếu",
				KeywordCount:    8,
				Snippet:         "...Tài liệu mật - Báo cáo quý 4 về hoạt động Ban Cơ yếu...",
				Location:        "Documents",
				DangerLevel:     "HIGH",
			},
			{
				FilePath:        "C:\\Users\\Admin\\Desktop\\Quyet-dinh-bi-mat.pdf",
				FileName:        "Quyet-dinh-bi-mat.pdf",
				FileType:        ".pdf",
				FileSize:        89200,
				ModifiedDate:    "2026-09-01T10:15:00Z",
				Classification:  "BÍ MẬT",
				MatchedKeywords: "bí mật, quyết định, chỉ thị",
				KeywordCount:    12,
				Snippet:         "...Văn bản bí mật - Quyết định điều động cán bộ...",
				Location:        "Desktop",
				DangerLevel:     "CRITICAL",
			},
		},
		TotalFiles:    47,
		TotalMatches:  2,
		CriticalCount: 1,
		HighCount:     1,
		Summary:       "Quét 47 file, phát hiện 2 văn bản Mật/Bí mật | ⚠ 1 CRITICAL (Tuyệt mật/Bí mật) | 1 HIGH (Mật)",
	}
}
