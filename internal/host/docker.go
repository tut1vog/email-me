package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// ErrNoContainer is Docker's "no such container".
var ErrNoContainer = errors.New("no such container")

// Docker runs the docker CLI.
type Docker interface {
	// Output runs docker and returns its standard output.
	Output(ctx context.Context, args ...string) (string, error)
	// Run runs docker attached to the given streams until it exits. It is
	// not tied to a context: a console ends by closing stdin, so the
	// gateway sees it go.
	Run(stdin io.Reader, stdout, stderr io.Writer, args ...string) error
}

// CLI is the docker command on PATH.
type CLI struct{}

func (CLI) Output(ctx context.Context, args ...string) (string, error) {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return string(out), dockerError(args, err, stderr.String())
	}
	return string(out), nil
}

func (CLI) Run(stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	cmd := exec.Command("docker", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	// Its own process group: Ctrl-C in the terminal goes to email-me, which
	// ends the command by closing stdin.
	ownProcessGroup(cmd)
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit // the command's own output already said why
		}
		return dockerError(args, err, "")
	}
	return nil
}

func dockerError(args []string, err error, stderr string) error {
	if errors.Is(err, exec.ErrNotFound) {
		return errors.New("docker is not installed or not on PATH: email-me runs in a Docker container")
	}
	stderr = strings.TrimSpace(stderr)
	if strings.Contains(stderr, "No such container") || strings.Contains(stderr, "No such object") {
		return ErrNoContainer
	}
	if stderr == "" {
		stderr = err.Error()
	}
	return fmt.Errorf("docker %s: %s", strings.Join(args[:min(2, len(args))], " "), stderr)
}
