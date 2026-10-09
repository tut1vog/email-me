package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// release serves a fake GitHub: the latest release's tag and, per tag, a
// tarball for linux/amd64 and its checksums.txt.
type release struct {
	latest   string
	binaries map[string]string // tag → the binary's contents
	badSum   bool              // checksums.txt lists a wrong digest
}

func tarball(t *testing.T, binary string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: "email-me", Mode: 0o755, Size: int64(len(binary)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(binary)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func (r *release) serve(t *testing.T) *Updater {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/"+Repo+"/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"tag_name": "` + r.latest + `", "name": "x"}`))
	})
	mux.HandleFunc("GET /download/{tag}/{asset}", func(w http.ResponseWriter, req *http.Request) {
		bin, ok := r.binaries[req.PathValue("tag")]
		if !ok {
			http.NotFound(w, req)
			return
		}
		tgz := tarball(t, bin)
		switch req.PathValue("asset") {
		case "email-me_linux_amd64.tar.gz":
			w.Write(tgz)
		case "checksums.txt":
			sum := sha256.Sum256(tgz)
			if r.badSum {
				sum[0] ^= 1
			}
			w.Write([]byte(hex.EncodeToString(sum[:]) + "  email-me_linux_amd64.tar.gz\n" +
				strings.Repeat("0", 64) + "  install.sh\n"))
		default:
			http.NotFound(w, req)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &Updater{API: srv.URL, Download: srv.URL + "/download", Client: srv.Client(), OS: "linux", Arch: "amd64"}
}

func TestLatest(t *testing.T) {
	u := (&release{latest: "v1.2.3"}).serve(t)
	got, err := u.Latest(context.Background())
	if err != nil || got != "v1.2.3" {
		t.Fatalf("Latest = %q, %v; want v1.2.3", got, err)
	}
}

func TestInstallReplacesTarget(t *testing.T) {
	u := (&release{binaries: map[string]string{"v1.2.3": "new binary"}}).serve(t)
	target := filepath.Join(t.TempDir(), "email-me")
	if err := os.WriteFile(target, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := u.Install(context.Background(), "v1.2.3", target); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "new binary" {
		t.Fatalf("target holds %q, %v; want the new binary", got, err)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o755 {
		t.Errorf("mode %v, want 0755", fi.Mode().Perm())
	}
	if entries, _ := os.ReadDir(filepath.Dir(target)); len(entries) != 1 {
		t.Errorf("left %d files in the directory, want only the binary", len(entries))
	}
}

func TestInstallRefusesABadChecksum(t *testing.T) {
	u := (&release{binaries: map[string]string{"v1.2.3": "new binary"}, badSum: true}).serve(t)
	target := filepath.Join(t.TempDir(), "email-me")
	if err := os.WriteFile(target, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := u.Install(context.Background(), "v1.2.3", target)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("Install = %v, want a checksum mismatch", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "old binary" {
		t.Errorf("target holds %q, want it untouched", got)
	}
	if entries, _ := os.ReadDir(filepath.Dir(target)); len(entries) != 1 {
		t.Errorf("left %d files in the directory, want only the binary", len(entries))
	}
}

func TestFetchUnknownVersionOrPlatform(t *testing.T) {
	u := (&release{binaries: map[string]string{"v1.2.3": "new binary"}}).serve(t)
	var buf bytes.Buffer
	if err := u.Fetch(context.Background(), "v9.9.9", &buf); err == nil {
		t.Error("Fetch of a missing release succeeded")
	}
	u.Arch = "riscv64"
	if err := u.Fetch(context.Background(), "v1.2.3", &buf); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Errorf("Fetch for an unreleased platform = %v, want not listed", err)
	}
	u.OS = "windows"
	if err := u.Fetch(context.Background(), "v1.2.3", &buf); err == nil || !strings.Contains(err.Error(), "Docker image") {
		t.Errorf("Fetch on windows = %v, want a pointer to the Docker image", err)
	}
}
