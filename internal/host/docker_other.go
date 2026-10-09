//go:build !unix

package host

import "os/exec"

func ownProcessGroup(*exec.Cmd) {}
