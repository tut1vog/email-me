// Package selfupdate replaces the running email-me binary with a release
// from GitHub, as install.sh does: it downloads the release's tarball for
// this OS and architecture, checks it against the release's checksums.txt,
// and renames the new binary over the old one.
package selfupdate

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Repo is the GitHub repository releases come from.
const Repo = "tut1vog/email-me"

// maxBinary bounds the extracted binary, so a bad tarball cannot fill the
// disk.
const maxBinary = 256 << 20

// Updater downloads releases.
type Updater struct {
	// API is the GitHub API base URL (https://api.github.com).
	API string
	// Download is the base URL of release assets
	// (https://github.com/tut1vog/email-me/releases/download).
	Download string
	Client   *http.Client
	// OS and Arch name the release asset, e.g. linux and arm64.
	OS, Arch string
}

// New returns an Updater for GitHub and this platform.
func New() *Updater {
	return &Updater{
		API:      "https://api.github.com",
		Download: "https://github.com/" + Repo + "/releases/download",
		Client:   &http.Client{Timeout: 5 * time.Minute},
		OS:       runtime.GOOS,
		Arch:     arch(),
	}
}

// arch is the release architecture for this machine: arm64 for an amd64
// binary that Rosetta runs on Apple silicon.
func arch() string {
	if runtime.GOOS == "darwin" && runtime.GOARCH == "amd64" {
		if out, err := exec.Command("sysctl", "-n", "sysctl.proc_translated").Output(); err == nil &&
			strings.TrimSpace(string(out)) == "1" {
			return "arm64"
		}
	}
	return runtime.GOARCH
}

// Asset is the release tarball's name for this platform.
func (u *Updater) Asset() string { return "email-me_" + u.OS + "_" + u.Arch + ".tar.gz" }

// Latest returns the tag of the latest release; prereleases are never
// latest.
func (u *Updater) Latest(ctx context.Context) (string, error) {
	body, err := u.get(ctx, u.API+"/repos/"+Repo+"/releases/latest")
	if err != nil {
		return "", fmt.Errorf("finding the latest release: %w", err)
	}
	var r struct {
		Tag string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Tag == "" {
		return "", errors.New("finding the latest release: GitHub's answer has no tag_name")
	}
	return r.Tag, nil
}

// Fetch downloads version's binary for this platform, checks it against
// the release's checksums.txt and writes it to w.
func (u *Updater) Fetch(ctx context.Context, version string, w io.Writer) error {
	switch u.OS {
	case "linux", "darwin":
	default:
		return fmt.Errorf("there are no release binaries for %s; use the Docker image instead", u.OS)
	}
	base := u.Download + "/" + version + "/"
	asset := u.Asset()
	sums, err := u.get(ctx, base+"checksums.txt")
	if err != nil {
		return fmt.Errorf("downloading checksums.txt of %s: %w", version, err)
	}
	want, ok := checksum(sums, asset)
	if !ok {
		return fmt.Errorf("%s is not listed in the checksums.txt of %s", asset, version)
	}
	tarball, err := u.get(ctx, base+asset)
	if err != nil {
		return fmt.Errorf("downloading %s of %s: %w", asset, version, err)
	}
	if got := sha256.Sum256(tarball); hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("checksum mismatch for %s of %s", asset, version)
	}
	return extract(tarball, w)
}

func (u *Updater) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBinary))
}

// checksum finds name's SHA-256 in a sha256sum listing.
func checksum(sums []byte, name string) (string, bool) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && (f[1] == name || f[1] == "*"+name) {
			return strings.ToLower(f[0]), true
		}
	}
	return "", false
}

// extract copies the email-me entry of a gzipped tarball to w.
func extract(tarball []byte, w io.Writer) error {
	zr, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return fmt.Errorf("reading the release tarball: %w", err)
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return errors.New("the release tarball holds no email-me binary")
		}
		if err != nil {
			return fmt.Errorf("reading the release tarball: %w", err)
		}
		if h.Typeflag == tar.TypeReg && h.Name == "email-me" {
			if h.Size > maxBinary {
				return errors.New("the release tarball's email-me binary is too large")
			}
			_, err := io.Copy(w, tr)
			return err
		}
	}
}

// Install writes version's binary over target. The new file is written
// next to target and renamed over it, so a running email-me keeps its old
// file and the new one appears whole. When target's directory is not
// writable, the copy and rename run under sudo, which may prompt on the
// terminal.
func (u *Updater) Install(ctx context.Context, version, target string) error {
	dir := filepath.Dir(target)
	f, err := os.CreateTemp(dir, ".email-me-*")
	if errors.Is(err, os.ErrPermission) {
		return u.installSudo(ctx, version, target)
	}
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := u.Fetch(ctx, version, f); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o755); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), target)
}

func (u *Updater) installSudo(ctx context.Context, version, target string) error {
	if _, err := exec.LookPath("sudo"); err != nil || os.Geteuid() == 0 {
		return fmt.Errorf("%s is not writable", filepath.Dir(target))
	}
	tmp, err := os.MkdirTemp("", "email-me-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	f, err := os.OpenFile(filepath.Join(tmp, "email-me"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if err := u.Fetch(ctx, version, f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s is not writable; using sudo\n", filepath.Dir(target))
	next := filepath.Join(filepath.Dir(target), ".email-me.new")
	for _, args := range [][]string{{"cp", f.Name(), next}, {"mv", "-f", next, target}} {
		cmd := exec.CommandContext(ctx, "sudo", args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("sudo %s: %w", args[0], err)
		}
	}
	return nil
}
