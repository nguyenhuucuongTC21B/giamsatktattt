// Package secretscan - keywords.go
// Danh sách từ khóa nhận diện văn bản Mật/Bí mật/Tuyệt mật
// File pure-string ĐA NỀN TẢNG (build được cả windows và non-windows)
package secretscan

import "strings"

// SecretKeyword chứa thông tin 1 từ khóa
type SecretKeyword struct {
	Word          string
	Classification string // MẬT | BÍ MẬT | TUYỆT MẬT | NGHI VẤN
}

// Danh sách từ khóa nhận diện văn bản Mật
var secretKeywords = []SecretKeyword{
	// Mật
	{"mật", "MẬT"},
	{"tài liệu mật", "MẬT"},
	{"văn bản mật", "MẬT"},
	{"tài liệu mậu", "MẬT"},
	{"mậu mật", "MẬT"},
	{"độ mật", "MẬT"},

	// Bí mật
	{"bí mật", "BÍ MẬT"},
	{"bi mat", "BÍ MẬT"},
	{"bimat", "BÍ MẬT"},
	{"tài liệu bí mật", "BÍ MẬT"},
	{"văn bản bí mật", "BÍ MẬT"},

	// Tuyệt mật
	{"tuyệt mật", "TUYỆT MẬT"},
	{"tuyet mat", "TUYỆT MẬT"},
	{"tuyetmat", "TUYỆT MẬT"},
	{"tài liệu tuyệt mật", "TUYỆT MẬT"},

	// Cao truyền / Nội bộ
	{"cao truyền", "NGHI VẤN"},
	{"cao truyen", "NGHI VẤN"},
	{"nội bộ", "NGHI VẤN"},
	{"noi bo", "NGHI VẤN"},
	{"chỉ thị", "NGHI VẤN"},
	{"chi thi", "NGHI VẤN"},

	// Quyết định / Lệnh
	{"quyết định", "NGHI VẤN"},
	{"quyet dinh", "NGHI VẤN"},
	{"lệnh điều động", "NGHI VẤN"},
	{"lenh dieu dong", "NGHI VẤN"},

	// An ninh / Cơ yếu
	{"ban cơ yếu", "NGHI VẤN"},
	{"ban co yeu", "NGHI VẤN"},
	{"an ninh mạng", "NGHI VẤN"},
	{"an ninh mang", "NGHI VẤN"},
	{"giám sát an ninh", "NGHI VẤN"},

	// Khác
	{"không phổ biến", "NGHI VẤN"},
	{"khong pho bien", "NGHI VẤN"},
	{"hạn chế phổ biến", "NGHI VẤN"},
	{"hạn chế lưu hành", "NGHI VẤN"},
	{"chỉ đạo", "NGHI VẤN"},
	{"triển khai", "NGHI VẤN"},

	// Mark of web/classification headers
	{"classified", "NGHI VẤN"},
	{"confidential", "NGHI VẤN"},
	{"top secret", "TUYỆT MẬT"},
	{"secret", "BÍ MẬT"},
	{"restricted", "NGHI VẤN"},
}

// MatchKeywords kiểm tra văn bản có chứa từ khóa Mật không
// Trả về: classification cao nhất, danh sách từ khóa match, số lần match, snippet
func MatchKeywords(content string) (classification string, matched []string, count int, snippet string) {
	if len(content) == 0 {
		return "", nil, 0, ""
	}

	lower := strings.ToLower(content)
	maxClassification := ""
	classificationRank := map[string]int{
		"":         0,
		"NGHI VẤN": 1,
		"MẬT":      2,
		"BÍ MẬT":   3,
		"TUYỆT MẬT": 4,
	}

	seen := map[string]bool{}

	for _, kw := range secretKeywords {
		kwLower := strings.ToLower(kw.Word)
		idx := strings.Index(lower, kwLower)
		if idx >= 0 {
			// Đếm số lần xuất hiện
			c := 0
			searchFrom := 0
			for {
				i := strings.Index(lower[searchFrom:], kwLower)
				if i < 0 {
					break
				}
				c++
				searchFrom += i + len(kwLower)
				if c > 100 {
					break // giới hạn
				}
			}

			matched = append(matched, kw.Word)
			count += c

			// Lấy snippet (đoạn văn xung quanh từ khóa đầu tiên)
			if snippet == "" && idx >= 0 {
				start := idx - 50
				if start < 0 {
					start = 0
				}
				end := idx + len(kwLower) + 100
				if end > len(content) {
					end = len(content)
				}
				snippet = content[start:end]
				if start > 0 {
					snippet = "..." + snippet
				}
				if end < len(content) {
					snippet = snippet + "..."
				}
			}

			// Cập nhật classification cao nhất
			if classificationRank[kw.Classification] > classificationRank[maxClassification] {
				maxClassification = kw.Classification
			}

			seen[kw.Word] = true
		}
	}

	return maxClassification, matched, count, snippet
}

// CalcDangerLevel tính mức độ nguy hiểm dựa vào classification + keyword count
func CalcDangerLevel(classification string, keywordCount int) string {
	switch classification {
	case "TUYỆT MẬT":
		return "CRITICAL"
	case "BÍ MẬT":
		return "CRITICAL"
	case "MẬT":
		if keywordCount >= 5 {
			return "CRITICAL"
		}
		return "HIGH"
	case "NGHI VẤN":
		if keywordCount >= 10 {
			return "HIGH"
		}
		return "MEDIUM"
	}
	return "LOW"
}
