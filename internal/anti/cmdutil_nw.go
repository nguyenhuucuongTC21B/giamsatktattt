//go:build !windows

package anti

import "os/exec"

func hideWindowCmd(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}
