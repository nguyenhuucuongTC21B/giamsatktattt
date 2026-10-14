//go:build windows

package secretscan

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

)

// ScanSecretDocs rà quét sâu văn bản Word/PDF trong:
//   - Desktop, Documents, Downloads của user
//   - Ổ USB / ổ ngoài (D:, E:, F:...)
//
// Đọc nội dung file, tìm từ khóa "Mật", "Bí mật", "Tuyệt mật"
func ScanSecretDocs() SecretScanResult {
	result := SecretScanResult{}

	up := os.Getenv("USERPROFILE")
	if up == "" {
		return result
	}

	// Danh sách thư mục cần quét
	scanDirs := []struct {
		Path  string
		Label string
	}{
		{filepath.Join(up, "Desktop"), "Desktop"},
		{filepath.Join(up, "Documents"), "Documents"},
		{filepath.Join(up, "Downloads"), "Downloads"},
	}

	// Thêm ổ USB/ổ ngoài
	for c := 'D'; c <= 'Z'; c++ {
		p := string(c) + `:\`
		if _, err := os.Stat(p); err == nil {
			scanDirs = append(scanDirs, struct{ Path, Label string }{p, "USB " + string(c) + ":"})
		}
	}

	// Giới hạn tổng số file quét
	maxFiles := 500
	fileCount := 0

	// Quét từng thư mục
	for _, dir := range scanDirs {
		filepath.WalkDir(dir.Path, func(p string, d os.DirEntry, err error) error {
			if err != nil || d == nil {
				return nil
			}

			// Bỏ qua thư mục hệ thống
			if d.IsDir() {
				lower := strings.ToLower(p)
				skipDirs := []string{"windows", "program files", "programdata",
					"appdata", "$recycle.bin", "system volume", "temp"}
				for _, sd := range skipDirs {
					if strings.Contains(lower, sd) {
						return filepath.SkipDir
					}
				}
				return nil
			}

			if fileCount >= maxFiles {
				return filepath.SkipDir
			}

			ext := strings.ToLower(filepath.Ext(p))
			if !isScannableFile(ext) {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.Size() > 10*1024*1024 {
				return nil
			}

			fileCount++
			result.TotalFiles++

			// Đọc nội dung file - có recover
			var content string
			func() {
				defer func() { recover() }()
				content = extractFileContent(p, ext)
			}()
			if content == "" {
				return nil
			}

			// Tìm từ khóa Mật
			classification, matched, count, snippet := MatchKeywords(content)
			if classification == "" {
				return nil
			}

			rec := SecretDocRecord{
				FilePath:        p,
				FileName:        filepath.Base(p),
				FileType:        ext,
				FileSize:        info.Size(),
				ModifiedDate:    info.ModTime().Format("2006-01-02 15:04:05"),
				Classification:  classification,
				MatchedKeywords: strings.Join(matched, ", "),
				KeywordCount:    count,
				Snippet:         snippet,
				Location:        dir.Label,
				DangerLevel:     CalcDangerLevel(classification, count),
			}

			result.Records = append(result.Records, rec)
			result.TotalMatches++

			switch rec.DangerLevel {
			case "CRITICAL":
				result.CriticalCount++
			case "HIGH":
				result.HighCount++
			}

			return nil
		})
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Quét %d file, phát hiện %d văn bản Mật/Bí mật",
		result.TotalFiles, result.TotalMatches))
	if result.CriticalCount > 0 {
		sb.WriteString(fmt.Sprintf(" | ⚠ %d CRITICAL", result.CriticalCount))
	}
	if result.HighCount > 0 {
		sb.WriteString(fmt.Sprintf(" | %d HIGH", result.HighCount))
	}
	result.Summary = sb.String()

	return result
}

// isScannableFile kiểm tra phần mở rộng
func isScannableFile(ext string) bool {
	switch ext {
	case ".docx", ".doc", ".xlsx", ".xlsm", ".pptx", ".ppt":
		return true
	case ".pdf":
		return true
	case ".txt", ".csv", ".rtf":
		return true
	}
	return false
}

// extractFileContent trích nội dung text từ file
func extractFileContent(path, ext string) string {
	switch ext {
	case ".docx", ".xlsx", ".xlsm", ".pptx":
		return extractFromOfficeXML(path)
	case ".doc", ".ppt":
		return extractFromBinary(path)
	case ".pdf":
		return extractFromPDF(path)
	case ".txt", ".csv", ".rtf":
		data, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return string(data)
	}
	return ""
}

// extractFromOfficeXML đọc .docx/.xlsx/.pptx (ZIP chứa XML)
func extractFromOfficeXML(path string) string {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return ""
	}
	defer zr.Close()

	var sb strings.Builder
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".xml") {
			continue
		}
		// Đọc TẤT CẢ file XML trong ZIP (không lọc quá chặt)
		// Vì nội dung text có thể nằm trong nhiều file khác nhau
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		text := extractTextFromXML(string(data))
		if text != "" {
			sb.WriteString(text + " ")
		}
	}
	return sb.String()
}

// extractTextFromXML trích text thuần từ XML
// Hỗ trợ UTF-8 (tiếng Việt có dấu)
func extractTextFromXML(xml string) string {
	// Phương án 1: <w:t>...</w:t> (Word)
	re1 := regexp.MustCompile(`<w:t[^>]*>([^<]+)</w:t>`)
	matches1 := re1.FindAllStringSubmatch(xml, -1)
	var parts []string
	for _, m := range matches1 {
		if len(m) > 1 {
			parts = append(parts, m[1])
		}
	}

	// Phương án 2: <a:t>...</a:t> (PowerPoint)
	if len(parts) == 0 {
		re2 := regexp.MustCompile(`<a:t[^>]*>([^<]+)</a:t>`)
		matches2 := re2.FindAllStringSubmatch(xml, -1)
		for _, m := range matches2 {
			if len(m) > 1 {
				parts = append(parts, m[1])
			}
		}
	}

	// Phương án 3: <text:p> hoặc <text:s> (Excel/LibreOffice)
	if len(parts) == 0 {
		re3 := regexp.MustCompile(`<(?:text:p|text:s|text:a)[^>]*>([^<]+)</`)
		matches3 := re3.FindAllStringSubmatch(xml, -1)
		for _, m := range matches3 {
			if len(m) > 1 {
				parts = append(parts, m[1])
			}
		}
	}

	// Phương án 4: Lấy TẤT CẢ text giữa > và < (catch-all)
	// Hỗ trợ UTF-8: lấy mọi ký tự không phải < >
	if len(parts) == 0 {
		re4 := regexp.MustCompile(`>([^<]{2,})<`)
		matches4 := re4.FindAllStringSubmatch(xml, -1)
		for _, m := range matches4 {
			if len(m) > 1 {
				s := strings.TrimSpace(m[1])
				if len(s) > 2 {
					parts = append(parts, s)
				}
			}
		}
	}

	return strings.Join(parts, " ")
}

// extractFromBinary đọc thô binary (.doc/.ppt cũ)
// Hỗ trợ cả UTF-16LE (Windows) và UTF-8
func extractFromBinary(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	var sb strings.Builder

	// Phương án 1: Trích ASCII text (ký tự 0x20-0x7E liên tục >=4 ký tự)
	re1 := regexp.MustCompile(`[\x20-\x7E]{4,}`)
	matches1 := re1.FindAllString(string(data), -1)
	for _, m := range matches1 {
		if len(m) > 10 {
			sb.WriteString(string(m) + " ")
		}
	}

	// Phương án 2: Trích UTF-16LE text (byte pair 0x00 + ASCII)
	// .doc cũ thường lưu text UTF-16LE
	i := 0
	for i+1 < len(data) {
		// Tìm chuỗi UTF-16LE: ASCII char + 0x00 liên tục
		if data[i] >= 0x20 && data[i] < 0x7F && data[i+1] == 0x00 {
			start := i
			for i+1 < len(data) && data[i] >= 0x20 && data[i] < 0x7F && data[i+1] == 0x00 {
				i += 2
			}
			if i-start >= 8 { // ít nhất 4 ký tự
				// Decode UTF-16LE
				chars := []byte{}
				for j := start; j < i; j += 2 {
					chars = append(chars, data[j])
				}
				sb.WriteString(string(chars) + " ")
			}
		} else {
			i++
		}
	}

	return sb.String()
}

// extractFromPDF trích text từ PDF
// Hỗ trợ: text trong parentheses, hex string, và text stream
func extractFromPDF(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	content := string(data)
	var sb strings.Builder

	// Phương án 1: Text trong parentheses (PDF operator Tj/TJ)
	// Hỗ trợ UTF-8 (bao gồm tiếng Việt có dấu)
	re1 := regexp.MustCompile(`\(([^)]{2,})\)`)
	matches1 := re1.FindAllStringSubmatch(content, -1)
	for _, m := range matches1 {
		if len(m) > 1 {
			// Unescape PDF string
			text := strings.ReplaceAll(m[1], "\\(", "(")
			text = strings.ReplaceAll(text, "\\)", ")")
			text = strings.ReplaceAll(text, "\\n", "\n")
			sb.WriteString(text + " ")
		}
	}

	// Phương án 2: Hex string trong <...>
	re2 := regexp.MustCompile(`<([0-9A-Fa-f]{4,})>`)
	matches2 := re2.FindAllStringSubmatch(content, -1)
	for _, m := range matches2 {
		if len(m) > 1 && len(m[1]) > 8 {
			hex := m[1]
			text := ""
			for i := 0; i+1 < len(hex); i += 2 {
				c := hexVal(hex[i])*16 + hexVal(hex[i+1])
				if c >= 32 && c < 127 {
					text += string(rune(c))
				}
			}
			if len(text) > 5 {
				sb.WriteString(text + " ")
			}
		}
	}

	// Phương án 3: text stream - tìm "BT ... ET" blocks
	// và trích text sau Tj/TJ operator
	re3 := regexp.MustCompile(`([^\s()<>]{2,})\s*Tj`)
	matches3 := re3.FindAllStringSubmatch(content, -1)
	for _, m := range matches3 {
		if len(m) > 1 {
			sb.WriteString(m[1] + " ")
		}
	}

	// Phương án 4: Tìm text có dấu tiếng Việt trực tiếp trong stream
	// PDF hiện đại lưu text UTF-8 trực tiếp
	re4 := regexp.MustCompile(`[\xC0-\xFF\x20-\x7E]{4,}`)
	matches4 := re4.FindAllString(content, -1)
	for _, m := range matches4 {
		if len(m) > 10 {
			sb.WriteString(m + " ")
		}
	}

	return sb.String()
}

func hexVal(c byte) int {
	if c >= '0' && c <= '9' {
		return int(c - '0')
	}
	if c >= 'a' && c <= 'f' {
		return int(c-'a') + 10
	}
	if c >= 'A' && c <= 'F' {
		return int(c-'A') + 10
	}
	return 0
}

// GetLastModifiedDate đọc ngày sửa đổi
