//go:build unix

package host

import (
	"os/exec"
	"syscall"
)

func ownProcessGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
