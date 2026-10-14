//go:build windows

package hardware

import (
	"bytes"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// scanPeripheralSessions truy vấn lịch sử từng lần cắm/rút thiết bị
// Trả về map[pnpDeviceID][]ConnectSession
//
// TỐI ƯU TỐC ĐỘ: giới hạn 15 giây cho wevtutil, bỏ qua nếu timeout
func scanPeripheralSessions() map[string][]ConnectSession {
	out := map[string][]ConnectSession{}

	// Phương án 1: Query Event Log Kernel-PnP (giới hạn 15s)
	sessions := queryKernelPnPSessions()
	if len(sessions) > 0 {
		for pnp, sess := range sessions {
			out[pnp] = sess
		}
	}

	// Phương án 2: Fallback SetupAPI log (nhanh hơn, chỉ đọc tail 500 dòng)
	if len(out) == 0 {
		setupSessions := parseSetupAPILog()
		for pnp, sess := range setupSessions {
			out[pnp] = sess
		}
	}

	return out
}

// queryKernelPnPSessions query event log với TIMEOUT 15 giây
// (wevtutil có thể treo 60-120s trên máy có nhiều event)
func queryKernelPnPSessions() map[string][]ConnectSession {
	out := map[string][]ConnectSession{}

	cmd := exec.Command("wevtutil", "qe", "Microsoft-Windows-Kernel-PnP/Operational",
		"/q:*[System[(EventID=20001 or EventID=20002)]]",
		"/c:100", "/rd:true", "/f:text")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	// Timeout 15 giây - nếu wevtutil chậm hơn, bỏ qua
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		// Timeout - kill wevtutil và trả rỗng
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return out
	}

	content := stdout.String()
	return parseKernelPnPEventLog(content)
}

// parseKernelPnPEventLog parse output của wevtutil cho Kernel-PnP events
func parseKernelPnPEventLog(content string) map[string][]ConnectSession {
	out := map[string][]ConnectSession{}

	dateRe := regexp.MustCompile(`(?i)Date:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})`)
	eventIDRe := regexp.MustCompile(`(?i)Event ID:\s*(\d+)`)
	deviceRe := regexp.MustCompile(`(?i)USB\\VID_[A-F0-9&PID_]+\\\S+`)

	events := strings.Split(content, "Event[")
	var currentTS, currentEventID, currentDevice string
	for i, ev := range events {
		if i == 0 {
			continue
		}
		currentTS = ""
		currentEventID = ""
		currentDevice = ""

		if m := dateRe.FindStringSubmatch(ev); len(m) > 1 {
			currentTS = m[1]
		}
		if m := eventIDRe.FindStringSubmatch(ev); len(m) > 1 {
			currentEventID = m[1]
		}
		if m := deviceRe.FindStringSubmatch(ev); len(m) > 0 {
			currentDevice = m[0]
		}

		if currentDevice == "" || currentTS == "" {
			continue
		}

		isArrival := currentEventID == "20001"
		sessions := out[currentDevice]
		if isArrival {
			sessions = append(sessions, ConnectSession{
				StartTime: currentTS,
				Source:    "Event Log",
			})
		} else {
			if len(sessions) > 0 && sessions[len(sessions)-1].EndTime == "" {
				sessions[len(sessions)-1].EndTime = currentTS
			}
		}
		out[currentDevice] = sessions
	}
	return out
}

// parseSetupAPILog fallback: đọc C:\Windows\inf\setupapi.dev.log
// Giới hạn 500 dòng cuối (nhanh hơn 2000 dòng)
func parseSetupAPILog() map[string][]ConnectSession {
	out := map[string][]ConnectSession{}

	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-Content 'C:\Windows\inf\setupapi.dev.log' -Tail 500 -ErrorAction SilentlyContinue`)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return out
	}

	content := stdout.String()
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "usb\\vid_") {
			continue
		}
		usbIdx := strings.Index(line, "USB\\")
		if usbIdx < 0 {
			continue
		}
		rest := line[usbIdx:]
		parts := strings.Fields(rest)
		if len(parts) == 0 {
			continue
		}
		pnp := parts[0]
		tsRe := regexp.MustCompile(`(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})`)
		var ts string
		if m := tsRe.FindStringSubmatch(line); len(m) > 1 {
			ts = strings.ReplaceAll(m[1], "/", "-")
		}
		if ts == "" {
			continue
		}
		sessions := out[pnp]
		sessions = append(sessions, ConnectSession{
			StartTime: ts,
			Source:    "SetupAPI log",
		})
		out[pnp] = sessions
	}
	return out
}
