//go:build windows

package network

import (
	"bytes"
	"os/exec"
	"strings"
	"time"
)

// LANConfigResult chứa thông tin cấu hình mạng nội bộ
type LANConfigResult struct {
	SMBv1Enabled  bool
	SMBv1Status   string
	LLMNRDisabled bool
	LLMNRStatus   string
	NetBIOSStatus string
	Summary       string
}

// getLANConfig kiểm tra SMBv1, LLMNR, NetBIOS over TCP/IP
// TIMEOUT 10 giây cho mỗi lệnh
func getLANConfig() LANConfigResult {
	out := LANConfigResult{}

	// 1. SMBv1
	cmd := hideWindowCmd("powershell", "-NoProfile", "-Command",
		"try{(Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol}catch{'ERR'}")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	runWithTimeout(cmd, 10*time.Second)
	smbOut := strings.ToLower(strings.TrimSpace(stdout.String()))
	if strings.Contains(smbOut, "true") {
		out.SMBv1Enabled = true
		out.SMBv1Status = "BẬT - RỦI RO EternalBlue!"
	} else if strings.Contains(smbOut, "false") {
		out.SMBv1Status = "Đã tắt"
	} else {
		out.SMBv1Status = "Không xác định (cần Admin)"
	}

	// 2. LLMNR
	cmd2 := hideWindowCmd("reg", "query",
		`HKLM\Software\Policies\Microsoft\Windows NT\DNSClient`, "/v", "TurnOffMulticast")
	var stdout2 bytes.Buffer
	cmd2.Stdout = &stdout2
	runWithTimeout(cmd2, 5*time.Second)
	if strings.Contains(stdout2.String(), "0x1") {
		out.LLMNRDisabled = true
		out.LLMNRStatus = "Đã tắt qua policy"
	} else {
		out.LLMNRStatus = "CHƯA tắt - rủi ro Responder/Poisoning"
	}

	// 3. NetBIOS
	cmd3 := hideWindowCmd("powershell", "-NoProfile", "-Command",
		`Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).NetbiosOptions }`)
	var stdout3 bytes.Buffer
	cmd3.Stdout = &stdout3
	runWithTimeout(cmd3, 10*time.Second)
	nbtOut := stdout3.String()
	hasEnabled := false
	for _, line := range strings.Split(nbtOut, "\n") {
		v := strings.TrimSpace(line)
		if v == "1" || v == "2" {
			hasEnabled = true
		}
	}
	if hasEnabled {
		out.NetBIOSStatus = "Bật - rủi ro poisoning"
	} else {
		out.NetBIOSStatus = "Đã tắt"
	}

	var sb strings.Builder
	sb.WriteString("SMBv1: " + out.SMBv1Status + "\n")
	sb.WriteString("LLMNR: " + out.LLMNRStatus + "\n")
	sb.WriteString("NetBIOS: " + out.NetBIOSStatus)
	out.Summary = sb.String()
	return out
}

// runWithTimeout chạy command với timeout, kill nếu quá lâu
func runWithTimeout(cmd *exec.Cmd, timeout time.Duration) {
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case <-done:
	case <-time.After(timeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}
}
