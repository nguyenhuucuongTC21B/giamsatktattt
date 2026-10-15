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

// ScanSecretDocs rà quét sâu văn bản Word/PDF trên TOÀN BỘ ổ đĩa
// Quét: C:\, D:\, E:\, F:\... (tất cả ổ đĩa có tồn tại)
// Bỏ qua thư mục hệ thống (Windows, Program Files, $Recycle.Bin...)
// Có ghi log debug vào file để troubleshoot
func ScanSecretDocs() SecretScanResult {
        result := SecretScanResult{}

        up := os.Getenv("USERPROFILE")
        if up == "" {
                up = `C:\Users\Default`
        }

        // Danh sách ổ đĩa cần quét - TẤT CẢ ổ từ C: đến Z:
        var scanRoots []struct {
                Path  string
                Label string
        }

        for c := 'C'; c <= 'Z'; c++ {
                p := string(c) + `:\`
                if _, err := os.Stat(p); err == nil {
                        label := "Ổ " + string(c) + ":"
                        scanRoots = append(scanRoots, struct{ Path, Label string }{p, label})
                }
        }

        // Ghi log debug
        logFile := filepath.Join(up, ".bcy-vks", "logs", "secretscan.log")
        os.MkdirAll(filepath.Dir(logFile), 0755)
        debugLog, _ := os.Create(logFile)
        if debugLog != nil {
                defer debugLog.Close()
                fmt.Fprintf(debugLog, "=== SecretScan Start ===\n")
                fmt.Fprintf(debugLog, "USERPROFILE: %s\n", up)
                for _, d := range scanRoots {
                        fmt.Fprintf(debugLog, "Scan root: %s (exists: %v)\n", d.Path, dirExists(d.Path))
                }
        }

        maxFiles := 2000 // Tăng lên 2000 file
        fileCount := 0

        // Danh sách thư mục hệ thống cần BỎ QUA - CHỈ dùng từ khóa DÀI, CHÍNH XÁC
        // KHÔNG dùng từ khóa ngắn như "go", "lib", "bin", "src" vì match nhầm thư mục tiếng Việt
        skipDirs := []string{
                "windows", "program files", "program files (x86)", "programdata",
                "$recycle.bin", "system volume information",
                "appdata", "node_modules", ".git", "__pycache__",
                "driverstore", "servicing", "softwaredistribution",
                "drivercache", "prefetch",
                "minidump", "microsoft.net", "internet explorer",
                "python312", "python311", "python310", "site-packages",
                "matplotlib", "numpy", "pandas", "scipy",
                "cryptography", "openssl",
                ".nuget", ".ollama", ".vscode", ".templateengine",
                ".cache", "__pycache__",
                "winsxs", "assembly",
        }

        for _, root := range scanRoots {
                if debugLog != nil {
                        fmt.Fprintf(debugLog, "\n=== Quét ổ: %s ===\n", root.Path)
                }

                dirFileCount := 0
                dirMatchCount := 0

                filepath.WalkDir(root.Path, func(p string, d os.DirEntry, err error) error {
                        if err != nil || d == nil {
                                return nil
                        }

                        // Bỏ qua thư mục hệ thống
                        if d.IsDir() {
                                lower := strings.ToLower(p)
                                for _, sd := range skipDirs {
                                        if strings.Contains(lower, sd) {
                                                if debugLog != nil {
                                                        fmt.Fprintf(debugLog, "SKIP dir: %s (matches: %s)\n", p, sd)
                                                }
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
                        dirFileCount++

                        if debugLog != nil {
                                fmt.Fprintf(debugLog, "Scanning: %s (%d bytes, ext=%s)\n", p, info.Size(), ext)
                        }

                        // Đọc nội dung - có recover
                        var content string
                        func() {
                                defer func() {
                                        if r := recover(); r != nil {
                                                if debugLog != nil {
                                                        fmt.Fprintf(debugLog, "  PANIC reading: %v\n", r)
                                                }
                                        }
                                }()
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

                        if debugLog != nil {
                                fmt.Fprintf(debugLog, "  ✅ FOUND: classification=%s, keywords=%v, count=%d\n",
                                        classification, matched, count)
                        }

                        // Xác định vị trí file
                        location := root.Label
                        // Nếu file nằm trong user profile, ghi rõ
                        if strings.HasPrefix(strings.ToLower(p), strings.ToLower(up)) {
                                rel, _ := filepath.Rel(up, p)
                                dirName := filepath.Dir(rel)
                                if dirName == "Desktop" || dirName == "Documents" || dirName == "Downloads" {
                                        location = dirName
                                }
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
                                Location:        location,
                                DangerLevel:     CalcDangerLevel(classification, count),
                        }

                        result.Records = append(result.Records, rec)
                        result.TotalMatches++
                        dirMatchCount++

                        switch rec.DangerLevel {
                        case "CRITICAL":
                                result.CriticalCount++
                        case "HIGH":
                                result.HighCount++
                        }

                        return nil
                })

                // Ghi nhận thư mục đã quét
                result.ScannedDirs = append(result.ScannedDirs, ScannedDir{
                        Path:       root.Path,
                        FileCount:  dirFileCount,
                        MatchCount: dirMatchCount,
                })

                if debugLog != nil {
                        fmt.Fprintf(debugLog, "Ổ %s: %d file scanned, %d matches\n",
                                root.Path, dirFileCount, dirMatchCount)
                }
        }

        result.LogFilePath = logFile

        var sb strings.Builder
        sb.WriteString(fmt.Sprintf("Quét %d file trên %d ổ đĩa, phát hiện %d văn bản Mật/Bí mật",
                result.TotalFiles, len(scanRoots), result.TotalMatches))
        if result.CriticalCount > 0 {
                sb.WriteString(fmt.Sprintf(" | ⚠ %d CRITICAL", result.CriticalCount))
        }
        if result.HighCount > 0 {
                sb.WriteString(fmt.Sprintf(" | %d HIGH", result.HighCount))
        }
        result.Summary = sb.String()

        if debugLog != nil {
                fmt.Fprintf(debugLog, "\n=== SecretScan Done: %d files scanned, %d matches ===\n",
                        result.TotalFiles, result.TotalMatches)
        }

        return result
}

func dirExists(path string) bool {
        info, err := os.Stat(path)
        return err == nil && info.IsDir()
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

// extractTextFromXML trích text thuần từ XML - hỗ trợ UTF-8
func extractTextFromXML(xml string) string {
        var parts []string

        // <w:t>...</w:t> (Word)
        re1 := regexp.MustCompile(`<w:t[^>]*>([^<]+)</w:t>`)
        for _, m := range re1.FindAllStringSubmatch(xml, -1) {
                if len(m) > 1 {
                        parts = append(parts, m[1])
                }
        }

        // <a:t>...</a:t> (PowerPoint)
        if len(parts) == 0 {
                re2 := regexp.MustCompile(`<a:t[^>]*>([^<]+)</a:t>`)
                for _, m := range re2.FindAllStringSubmatch(xml, -1) {
                        if len(m) > 1 {
                                parts = append(parts, m[1])
                        }
                }
        }

        // Catch-all: >([^<]{2,})< - lấy mọi text
        if len(parts) == 0 {
                re4 := regexp.MustCompile(`>([^<]{2,})<`)
                for _, m := range re4.FindAllStringSubmatch(xml, -1) {
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
func extractFromBinary(path string) string {
        data, err := os.ReadFile(path)
        if err != nil {
                return ""
        }

        var sb strings.Builder

        // ASCII text
        re1 := regexp.MustCompile(`[\x20-\x7E]{4,}`)
        for _, m := range re1.FindAllString(string(data), -1) {
                if len(m) > 10 {
                        sb.WriteString(string(m) + " ")
                }
        }

        // UTF-16LE text
        i := 0
        for i+1 < len(data) {
                if data[i] >= 0x20 && data[i] < 0x7F && data[i+1] == 0x00 {
                        start := i
                        for i+1 < len(data) && data[i] >= 0x20 && data[i] < 0x7F && data[i+1] == 0x00 {
                                i += 2
                        }
                        if i-start >= 8 {
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

// extractFromPDF trích text từ PDF - 4 phương án
func extractFromPDF(path string) string {
        data, err := os.ReadFile(path)
        if err != nil {
                return ""
        }
        content := string(data)
        var sb strings.Builder

        // 1. Text trong parentheses
        re1 := regexp.MustCompile(`\(([^)]{2,})\)`)
        for _, m := range re1.FindAllStringSubmatch(content, -1) {
                if len(m) > 1 {
                        text := strings.ReplaceAll(m[1], "\\(", "(")
                        text = strings.ReplaceAll(text, "\\)", ")")
                        sb.WriteString(text + " ")
                }
        }

        // 2. Hex string
        re2 := regexp.MustCompile(`<([0-9A-Fa-f]{4,})>`)
        for _, m := range re2.FindAllStringSubmatch(content, -1) {
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

        // 3. UTF-8 text có dấu (byte 0xC0-0xFF = multi-byte UTF-8)
        re3 := regexp.MustCompile(`[\xC0-\xFF\x20-\x7E]{4,}`)
        for _, m := range re3.FindAllString(content, -1) {
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
