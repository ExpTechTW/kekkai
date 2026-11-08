package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateDownloadURL(t *testing.T) {
	ok := []string{
		"https://github.com/ExpTechTW/kekkai/releases/download/v1/kekkai-linux-amd64",
		"https://objects.githubusercontent.com/github-production-release-asset-2e65be/a",
		"https://release-assets.githubusercontent.com/github-production-release-asset/a",
	}
	for _, raw := range ok {
		if err := validateDownloadURL(raw); err != nil {
			t.Errorf("validateDownloadURL(%q): %v", raw, err)
		}
	}
	bad := []string{
		"http://github.com/foo",
		"https://evil.example/kekkai",
		"https://github.com.evil.example/foo",
		"https://objects.githubusercontent.com.evil.example/a",
		"https://api.github.com/repos/ExpTechTW/kekkai/releases/latest",
		"",
	}
	for _, raw := range bad {
		if err := validateDownloadURL(raw); err == nil {
			t.Errorf("validateDownloadURL(%q) accepted", raw)
		}
	}
}

func TestVerifySHA256File(t *testing.T) {
	dir := t.TempDir()
	body := []byte("hello")
	path := filepath.Join(dir, "kekkai-linux-amd64")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	sums := filepath.Join(dir, "SHA256SUMS")
	text := digest + "  kekkai-linux-amd64\n" + digest + " *kekkai.sh\n"
	if err := os.WriteFile(sums, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256File(path, "kekkai-linux-amd64", sums); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "kekkai.sh")
	if err := os.WriteFile(script, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256File(script, "kekkai.sh", sums); err != nil {
		t.Fatalf("star prefix: %v", err)
	}
	if err := verifySHA256File(path, "missing", sums); err == nil {
		t.Fatal("expected missing entry")
	}
	if err := os.WriteFile(path, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256File(path, "kekkai-linux-amd64", sums); err == nil {
		t.Fatal("expected checksum mismatch")
	}
}
