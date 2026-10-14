// Package secretscan - keywords.go
// Danh sách từ khóa nhận diện văn bản Mật/Bí mật/Tuyệt mật
// Xây dựng dựa trên Luật Bảo vệ bí mật nhà nước và quy định VKSNDTC
// File pure-string ĐA NỀN TẢNG (build được cả windows và non-windows)
package secretscan

import "strings"

// SecretKeyword chứa thông tin 1 từ khóa
type SecretKeyword struct {
	Word          string
	Classification string // MẬT | BÍ MẬT | TUYỆT MẬT | NGHI VẤN
}

// Danh sách 59+ từ khóa độ mật ngành Kiểm sát
// Dựa trên Luật Bảo vệ bí mật nhà nước và quy định VKSNDTC
var secretKeywords = []SecretKeyword{
	// === NHÓM 1: Định danh độ mật chính thức (12 từ) ===
	{"tuyệt mật", "TUYỆT MẬT"},
	{"tuyet mat", "TUYỆT MẬT"},
	{"tuyetmat", "TUYỆT MẬT"},
	{"tối mật", "TUYỆT MẬT"},
	{"toi mat", "TUYỆT MẬT"},
	{"toimat", "TUYỆT MẬT"},
	{"mật", "MẬT"},
	{"bí mật", "BÍ MẬT"},
	{"bi mat", "BÍ MẬT"},
	{"bimat", "BÍ MẬT"},
	{"tài liệu mật", "MẬT"},
	{"văn bản mật", "MẬT"},
	{"độ mật", "MẬT"},
	{"bí mật nhà nước", "TUYỆT MẬT"},
	{"bi mat nha nuoc", "TUYỆT MẬT"},
	{"bí mật công tác", "BÍ MẬT"},
	{"hồ sơ mật", "MẬT"},
	{"tin mật", "MẬT"},
	{"án mật", "MẬT"},
	{"mậu mật", "MẬT"},
	{"tài liệu mậu", "MẬT"},

	// === NHÓM 2: Cơ quan, nghiệp vụ cơ yếu và mã hóa (11 từ) ===
	{"ban cơ yếu", "BÍ MẬT"},
	{"ban co yeu", "BÍ MẬT"},
	{"cơ yếu", "BÍ MẬT"},
	{"co yeu", "BÍ MẬT"},
	{"mã dịch", "BÍ MẬT"},
	{"ma dich", "BÍ MẬT"},
	{"điện mật", "MẬT"},
	{"dien mat", "MẬT"},
	{"giải mã", "BÍ MẬT"},
	{"giai ma", "BÍ MẬT"},
	{"khóa mã", "BÍ MẬT"},
	{"khoa ma", "BÍ MẬT"},
	{"mật mã", "BÍ MẬT"},
	{"mat ma", "BÍ MẬT"},
	{"sản phẩm mật mã", "BÍ MẬT"},
	{"điện mã", "MẬT"},
	{"dien ma", "MẬT"},
	{"điện cơ yếu", "BÍ MẬT"},
	{"dien co yeu", "BÍ MẬT"},
	{"trưởng ban cơ yếu", "TUYỆT MẬT"},
	{"truong ban co yeu", "TUYỆT MẬT"},

	// === NHÓM 3: Tin tức nghiệp vụ kiểm sát, điều tra (20 từ) ===
	{"tin an ninh quốc gia", "TUYỆT MẬT"},
	{"tin an ninh quoc gia", "TUYỆT MẬT"},
	{"chống phản động", "TUYỆT MẬT"},
	{"chong phan dong", "TUYỆT MẬT"},
	{"gián điệp", "TUYỆT MẬT"},
	{"gian diep", "TUYỆT MẬT"},
	{"khủng bố", "TUYỆT MẬT"},
	{"khung bo", "TUYỆT MẬT"},
	{"xâm phạm an ninh", "TUYỆT MẬT"},
	{"xam pham an ninh", "TUYỆT MẬT"},
	{"bí mật điều tra", "TUYỆT MẬT"},
	{"bi mat dieu tra", "TUYỆT MẬT"},
	{"kế hoạch điều tra", "TUYỆT MẬT"},
	{"ke hoach dieu tra", "TUYỆT MẬT"},
	{"biện pháp điều tra", "TUYỆT MẬT"},
	{"bien phap dieu tra", "TUYỆT MẬT"},
	{"điều tra đặc biệt", "TUYỆT MẬT"},
	{"dieu tra dac biet", "TUYỆT MẬT"},
	{"trinh sát", "TUYỆT MẬT"},
	{"trinh sat", "TUYỆT MẬT"},
	{"biện pháp trinh sát", "TUYỆT MẬT"},
	{"bien phap trinh sat", "TUYỆT MẬT"},
	{"người tố giác", "TUYỆT MẬT"},
	{"nguoi to giao", "TUYỆT MẬT"},
	{"người báo tin", "TUYỆT MẬT"},
	{"nguoi bao tin", "TUYỆT MẬT"},
	{"bảo vệ người làm chứng", "TUYỆT MẬT"},
	{"bao ve nguoi lam chung", "TUYỆT MẬT"},
	{"danh tính nhân chứng", "TUYỆT MẬT"},
	{"danh tinh nhan chung", "TUYỆT MẬT"},
	{"kế hoạch bắt", "TUYỆT MẬT"},
	{"ke hoach bat", "TUYỆT MẬT"},
	{"khám xét khẩn cấp", "TUYỆT MẬT"},
	{"kham xet khan cap", "TUYỆT MẬT"},
	{"bắt khẩn cấp", "TUYỆT MẬT"},
	{"bat khan cap", "TUYỆT MẬT"},
	{"vụ án đặc biệt nghiêm trọng", "TUYỆT MẬT"},
	{"vu an dac biet nghiem trong", "TUYỆT MẬT"},
	{"phương án tác chiến", "TUYỆT MẬT"},
	{"phuong an tac chien", "TUYỆT MẬT"},

	// === NHÓM 4: Quyết định nội bộ, nhân sự và thanh tra (16 từ) ===
	{"nhân sự xét duyệt", "MẬT"},
	{"nhan su xet duyet", "MẬT"},
	{"quy hoạch cán bộ", "MẬT"},
	{"quy hoach can bo", "MẬT"},
	{"kết luận thanh tra", "MẬT"},
	{"ket luan thanh tra", "MẬT"},
	{"hồ sơ nhân sự", "MẬT"},
	{"ho so nhan su", "MẬT"},
	{"kỷ luật nội bộ", "MẬT"},
	{"ky luat noi bo", "MẬT"},
	{"nguồn tin nội bộ", "MẬT"},
	{"nguon tin noi bo", "MẬT"},
	{"báo cáo chuyên đề an ninh", "MẬT"},
	{"bao cao chuyen de an ninh", "MẬT"},
	{"đề án tổ chức", "MẬT"},
	{"de an to chuc", "MẬT"},
	{"dự thảo nghị quyết", "MẬT"},
	{"du thao nghi quyet", "MẬT"},
	{"văn bản nội bộ", "NGHI VẤN"},
	{"van ban noi bo", "NGHI VẤN"},
	{"chỉ đạo của viện trưởng", "MẬT"},
	{"chi dao cua vien truong", "MẬT"},
	{"kết luận nội dung tố cáo", "MẬT"},
	{"ket luan noi dung to cao", "MẬT"},
	{"xử lý cán bộ", "MẬT"},
	{"xu ly can bo", "MẬT"},
	{"tài liệu chưa công bố", "MẬT"},
	{"tai lieu chua cong bo", "MẬT"},
	{"văn bản lưu hành nội bộ", "MẬT"},
	{"van ban luu hanh noi bo", "MẬT"},
	{"bí mật công nghệ thông tin", "BÍ MẬT"},
	{"bi mat cong nghe thong tin", "BÍ MẬT"},

	// === Bổ sung thêm: Các từ khóa phụ trợ ===
	{"chỉ thị", "NGHI VẤN"},
	{"chi thi", "NGHI VẤN"},
	{"quyết định", "NGHI VẤN"},
	{"quyet dinh", "NGHI VẤN"},
	{"lệnh điều động", "NGHI VẤN"},
	{"lenh dieu dong", "NGHI VẤN"},
	{"an ninh mạng", "NGHI VẤN"},
	{"an ninh mang", "NGHI VẤN"},
	{"giám sát an ninh", "NGHI VẤN"},
	{"không phổ biến", "NGHI VẤN"},
	{"khong pho bien", "NGHI VẤN"},
	{"hạn chế phổ biến", "NGHI VẤN"},
	{"hạn chế lưu hành", "NGHI VẤN"},
	{"chỉ đạo", "NGHI VẤN"},
	{"triển khai", "NGHI VẤN"},
	{"classified", "NGHI VẤN"},
	{"confidential", "BÍ MẬT"},
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
		"":          0,
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
					break
				}
			}

			if !seen[kw.Word] {
				matched = append(matched, kw.Word)
				seen[kw.Word] = true
			}
			count += c

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

			if classificationRank[kw.Classification] > classificationRank[maxClassification] {
				maxClassification = kw.Classification
			}
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
