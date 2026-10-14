//go:build windows

package network

import (
	"os/exec"
	"syscall"
)

// hideWindowCmd tạo exec.Command với CREATE_NO_WINDOW flag
// để không hiện cửa sổ CMD khi chạy lệnh
func hideWindowCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	return cmd
}
