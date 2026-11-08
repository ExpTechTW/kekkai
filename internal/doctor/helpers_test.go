package doctor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGrepLine(t *testing.T) {
	lines := strings.Split("noise\nstate=failed\nstate=later\ndetail= see journal \ntarget_version=\n", "\n")
	if got := grepLine(lines, "state"); got != "failed" {
		t.Fatalf("state=%q", got)
	}
	if got := grepLine(lines, "detail"); got != "see journal" {
		t.Fatalf("detail=%q", got)
	}
	if got := grepLine(lines, "target_version"); got != "" {
		t.Fatalf("empty value=%q", got)
	}
	if got := grepLine(lines, "missing"); got != "?" {
		t.Fatalf("missing=%q", got)
	}
	if got := grepLine(lines, "stateextra"); got != "?" {
		t.Fatalf("prefix key=%q", got)
	}
}

func TestBpffsMounted(t *testing.T) {
	if !bpffsMounted("sysfs /sys sysfs rw 0 0\nbpf /sys/fs/bpf bpf rw,mode=700 0 0\n") {
		t.Fatal("proc mounts")
	}
	if !bpffsMounted("bpf on /sys/fs/bpf type bpf (rw)\n") {
		t.Fatal("mount(8) line")
	}
	if bpffsMounted("proc /proc proc rw 0 0\n") {
		t.Fatal("unrelated mounts")
	}
}

func TestSHA256FilePrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kekkai")
	body := []byte("abc")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := sha256File(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:6])
	if got != want || len(got) != 12 {
		t.Fatalf("sha256File=%s want %s", got, want)
	}
}

func TestNativeCapable(t *testing.T) {
	if !nativeCapable("ixgbe") || !nativeCapable("ena") {
		t.Fatal("known native drivers")
	}
	if nativeCapable("virtio_net") || nativeCapable("e1000") || nativeCapable("") {
		t.Fatal("driver treated as native")
	}
}

func TestRenderPlain(t *testing.T) {
	r := New()
	sec := r.Section("kernel / ebpf")
	sec.Add(Result{Status: StatusOK, Title: "BTF", Detail: "present"})
	sec.Add(Result{Status: StatusWarn, Title: "NIC driver", Detail: "virtio_net", Suggestions: []string{"use generic"}})
	sec.Add(Result{Status: StatusError, Title: "bpffs", Detail: "not mounted"})
	var buf bytes.Buffer
	r.Render(&buf, false)
	got := buf.String()
	for _, want := range []string{
		"  ◈ KEKKAI doctor  結界 ·  diagnostic report",
		"  ○ KERNEL / EBPF",
		"    ✓  BTF                          present",
		"    ⚠  NIC driver                   virtio_net",
		"       → use generic",
		"    ✗  bpffs                        not mounted",
		"  issues detected  3 checks · 1 ok · 1 warn · 1 error",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q\n%s", want, got)
		}
	}
	if r.ExitCode() != 1 {
		t.Fatalf("exit=%d", r.ExitCode())
	}
}
