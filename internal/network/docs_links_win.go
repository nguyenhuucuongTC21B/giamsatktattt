//go:build windows

package network

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DocumentLinksResult chứa thông tin URL trong tài liệu
type DocumentLinksResult struct {
	TotalDocs       int
	TotalLinks      int
	SuspiciousLinks int
	SuspiciousURLs  []string
	Summary         string
}

// scanDocumentsForLinks rà quét .docx/.xlsx/.pptx/.pdf trong Desktop, Documents, Downloads
func scanDocumentsForLinks() DocumentLinksResult {
	out := DocumentLinksResult{}

	up := os.Getenv("USERPROFILE")
	if up == "" {
		return out
	}

	roots := []string{
		filepath.Join(up, "Desktop"),
		filepath.Join(up, "Documents"),
		filepath.Join(up, "Downloads"),
	}

	extMap := map[string]func(string) []string{
		".docx": extractLinksFromOffice,
		".xlsx": extractLinksFromOffice,
		".pptx": extractLinksFromOffice,
		".pdf":  extractLinksFromPDF,
	}

	for _, root := range roots {
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d == nil || d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			fn, ok := extMap[ext]
			if !ok {
				return nil
			}
			out.TotalDocs++
			links := fn(p)
			if len(links) == 0 {
				return nil
			}
			seen := map[string]bool{}
			for _, l := range links {
				if seen[l] {
					continue
				}
				seen[l] = true
				out.TotalLinks++
				low := strings.ToLower(l)
				for _, bl := range blacklistedDomains {
					if strings.Contains(low, bl) {
						out.SuspiciousLinks++
						if len(out.SuspiciousURLs) < 20 {
							out.SuspiciousURLs = append(out.SuspiciousURLs,
								fmt.Sprintf("[%s] %s", filepath.Base(p), l))
						}
						break
					}
				}
			}
			return nil
		})
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Quét %d tài liệu, tìm %d link, %d nghi vấn",
		out.TotalDocs, out.TotalLinks, out.SuspiciousLinks))
	if len(out.SuspiciousURLs) > 0 {
		sb.WriteString(":\n")
		for i, url := range out.SuspiciousURLs {
			if i >= 5 {
				sb.WriteString(fmt.Sprintf("\n  ... và %d link khác", len(out.SuspiciousURLs)-5))
				break
			}
			sb.WriteString("\n  • " + url)
		}
	}
	out.Summary = sb.String()
	return out
}

// extractLinksFromOffice trích URL từ .docx/.xlsx/.pptx (file ZIP)
func extractLinksFromOffice(path string) []string {
	out := []string{}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return out
	}
	defer zr.Close()
	for _, f := range zr.File {
		if !(strings.HasSuffix(f.Name, ".xml") || strings.HasSuffix(f.Name, ".rels")) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		s := strings.ReplaceAll(string(data), "&amp;", "&")
		out = append(out, urlRegex.FindAllString(s, -1)...)
	}
	return out
}

// extractLinksFromPDF trích URL từ PDF (regex trên byte stream)
func extractLinksFromPDF(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return urlRegex.FindAllString(string(data), -1)
}

// urlRegex - phải match với regex dùng ở dnscache (phải có biến này)
var urlRegex = regexp.MustCompile(`https?://[a-zA-Z0-9.\-_/:%?=&#+~]+`)
