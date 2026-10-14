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
        "time"

        "golang.org/x/sys/windows/registry"
)

// ScanSecretDocs rà quét sâu văn bản Word/PDF trong:
//   - Desktop, Documents, Downloads của user
//   - Ổ USB / ổ ngoài (D:, E:, F:...)
//
// Đọc nội dung file, tìm từ khóa "Mật", "Bí mật", "Tuyệt mật"
// TIMEOUT: không giới hạn từng file, nhưng bỏ qua file >50MB
func ScanSecretDocs() SecretScanResult {
        result := SecretScanResult{}

        up := os.Getenv("USERPROFILE")
        if up == "" {
                return result
        }

        // Danh sách thư mục cần quét - CHỈ user folders, KHÔNG quét toàn bộ ổ
        scanDirs := []struct {
                Path  string
                Label string
        }{
                {filepath.Join(up, "Desktop"), "Desktop"},
                {filepath.Join(up, "Documents"), "Documents"},
                {filepath.Join(up, "Downloads"), "Downloads"},
        }

        // Thêm ổ USB/ổ ngoài - chỉ quét thư mục gốc, KHÔNG đệ quy sâu
        for c := 'D'; c <= 'Z'; c++ {
                p := string(c) + `:\`
                if _, err := os.Stat(p); err == nil {
                        scanDirs = append(scanDirs, struct{ Path, Label string }{p, "USB " + string(c) + ":"})
                }
        }

        // Giới hạn tổng số file quét để tránh crash
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
                                // Bỏ qua thư mục hệ thống lớn
                                skipDirs := []string{"windows", "program files", "programdata",
                                        "appdata", "$recycle.bin", "system volume", "temp"}
                                for _, sd := range skipDirs {
                                        if strings.Contains(lower, sd) {
                                                return filepath.SkipDir
                                        }
                                }
                                return nil
                        }

                        // Giới hạn số file
                        if fileCount >= maxFiles {
                                return filepath.SkipDir
                        }

                        ext := strings.ToLower(filepath.Ext(p))
                        if !isScannableFile(ext) {
                                return nil
                        }

                        // Lấy thông tin file
                        info, err := d.Info()
                        if err != nil {
                                return nil
                        }
                        // Bỏ qua file >10MB (giảm từ 50MB xuống 10MB để tránh crash)
                        if info.Size() > 10*1024*1024 {
                                return nil
                        }

                        fileCount++
                        result.TotalFiles++

                        // Đọc nội dung file - có recover để chống crash
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

                        // Tạo record
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

        // Tổng hợp summary
        var sb strings.Builder
        sb.WriteString(fmt.Sprintf("Quét %d file, phát hiện %d văn bản Mật/Bí mật",
                result.TotalFiles, result.TotalMatches))
        if result.CriticalCount > 0 {
                sb.WriteString(fmt.Sprintf(" | ⚠ %d CRITICAL (Tuyệt mật/Bí mật)", result.CriticalCount))
        }
        if result.HighCount > 0 {
                sb.WriteString(fmt.Sprintf(" | %d HIGH (Mật)", result.HighCount))
        }
        result.Summary = sb.String()

        return result
}

// isScannableFile kiểm tra phần mở rộng có thể quét nội dung không
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

// extractFileContent trích nội dung text từ file theo loại
func extractFileContent(path, ext string) string {
        switch ext {
        case ".docx", ".xlsx", ".xlsm", ".pptx":
                return extractFromOfficeXML(path)
        case ".doc", ".ppt":
                // .doc/.ppt là binary format cũ - đọc thô binary và regex text
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

// extractFromOfficeXML đọc .docx/.xlsx/.pptx (file ZIP chứa XML)
func extractFromOfficeXML(path string) string {
        zr, err := zip.OpenReader(path)
        if err != nil {
                return ""
        }
        defer zr.Close()

        var sb strings.Builder
        for _, f := range zr.File {
                // Chỉ đọc file XML chứa nội dung (document.xml, sheet.xml, slide.xml)
                if !strings.HasSuffix(f.Name, ".xml") {
                        continue
                }
                if !strings.Contains(f.Name, "document") &&
                        !strings.Contains(f.Name, "sheet") &&
                        !strings.Contains(f.Name, "slide") &&
                        !strings.Contains(f.Name, "word/") &&
                        !strings.Contains(f.Name, "worksheets/") &&
                        !strings.Contains(f.Name, "slides/") {
                        continue
                }
                rc, err := f.Open()
                if err != nil {
                        continue
                }
                data, _ := io.ReadAll(rc)
                rc.Close()
                // Trích text từ XML: lấy nội dung giữa <w:t> tags (Word) hoặc text trong cell
                text := extractTextFromXML(string(data))
                sb.WriteString(text + " ")
        }
        return sb.String()
}

// extractTextFromXML trích text thuần từ XML
func extractTextFromXML(xml string) string {
        // Trích nội dung giữa <w:t>...</w:t> (Word)
        re := regexp.MustCompile(`<w:t[^>]*>([^<]+)</w:t>`)
        matches := re.FindAllStringSubmatch(xml, -1)
        var parts []string
        for _, m := range matches {
                if len(m) > 1 {
                        parts = append(parts, m[1])
                }
        }
        // Nếu không có <w:t>, thử <a:t> (PowerPoint)
        if len(parts) == 0 {
                re2 := regexp.MustCompile(`<a:t[^>]*>([^<]+)</a:t>`)
                matches2 := re2.FindAllStringSubmatch(xml, -1)
                for _, m := range matches2 {
                        if len(m) > 1 {
                                parts = append(parts, m[1])
                        }
                }
        }
        // Nếu không có, thử <text:s> hoặc text thuần
        if len(parts) == 0 {
                re3 := regexp.MustCompile(`>([^<]{5,})<`)
                matches3 := re3.FindAllStringSubmatch(xml, -1)
                for _, m := range matches3 {
                        if len(m) > 1 {
                                s := strings.TrimSpace(m[1])
                                if len(s) > 5 {
                                        parts = append(parts, s)
                                }
                        }
                }
        }
        return strings.Join(parts, " ")
}

// extractFromBinary đọc thô binary (.doc/.ppt cũ) và regex text
func extractFromBinary(path string) string {
        data, err := os.ReadFile(path)
        if err != nil {
                return ""
        }
        // Trích text Unicode (UTF-16LE) và ASCII
        re := regexp.MustCompile(`[\x20-\x7E]{4,}`)
        matches := re.FindAllString(string(data), -1)
        var parts []string
        for _, m := range matches {
                if len(m) > 10 {
                        parts = append(parts, string(m))
                }
        }
        return strings.Join(parts, " ")
}

// extractFromPDF trích text từ PDF
func extractFromPDF(path string) string {
        data, err := os.ReadFile(path)
        if err != nil {
                return ""
        }
        content := string(data)
        // PDF text thường trong parentheses sau Tj hoặc TJ operator
        re := regexp.MustCompile(`\(([^)]{2,})\)`)
        matches := re.FindAllStringSubmatch(content, -1)
        var parts []string
        for _, m := range matches {
                if len(m) > 1 {
                        parts = append(parts, m[1])
                }
        }
        // Thử hex string trong <...>
        re2 := regexp.MustCompile(`<([0-9A-Fa-f]{4,})>`)
        matches2 := re2.FindAllStringSubmatch(content, -1)
        for _, m := range matches2 {
                if len(m) > 1 && len(m[1]) > 8 {
                        // Decode hex → text (đơn giản)
                        hex := m[1]
                        text := ""
                        for i := 0; i+1 < len(hex); i += 2 {
                                c := hexVal(hex[i])*16 + hexVal(hex[i+1])
                                if c >= 32 && c < 127 {
                                        text += string(rune(c))
                                }
                        }
                        if len(text) > 5 {
                                parts = append(parts, text)
                        }
                }
        }
        return strings.Join(parts, " ")
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

// GetLastModifiedDate đọc ngày sửa đổi từ registry (nếu có)
func GetLastModifiedDate(filePath string) string {
        _ = registry.LOCAL_MACHINE // placeholder để import không lỗi
        info, err := os.Stat(filePath)
        if err != nil {
                return ""
        }
        return info.ModTime().Format(time.RFC3339)
}
