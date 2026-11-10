package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileCommand(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"profile", "--client", "balanced"}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("exit code %d, stderr=%s", exitCode, stderr.String())
	}
	for _, directive := range []string{"jc=6\n", "s4=32\n", "h4=4001-4999\n"} {
		if !strings.Contains(stdout.String(), directive) {
			t.Errorf("output is missing %q", directive)
		}
	}
}

func TestProfileCommandCanGenerateHeaderProtection(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"profile", "--header-protection", "low-bandwidth"}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("exit code %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "header_protection_key=") {
		t.Fatal("header protection key was not generated")
	}
	if strings.Contains(stdout.String(), "jc=") {
		t.Fatal("server profile unexpectedly contains junk packets")
	}
}

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"version"}, &stdout, &stderr); exitCode != 0 {
		t.Fatalf("version failed with exit code %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "uservone-amneziawg") || !strings.Contains(stdout.String(), "b5928efb") {
		t.Fatalf("unexpected version output: %q", stdout.String())
	}
}

func TestVersionJSONCommand(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"version-json"}, &stdout, &stderr); exitCode != 0 {
		t.Fatalf("version-json failed with exit code %d: %s", exitCode, stderr.String())
	}
	var info map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &info); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	for _, key := range []string{"product", "version", "commit", "upstream_commit", "go_version", "os", "arch"} {
		if info[key] == "" {
			t.Errorf("version-json field %q is empty", key)
		}
	}
	if info["product"] != "uservone-amneziawg" || !strings.HasPrefix(info["upstream_commit"], "b5928efb") {
		t.Fatalf("unexpected version-json: %#v", info)
	}
}

func TestCheckConfigCommand(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	validPath := filepath.Join(directory, "valid.conf")
	if err := os.WriteFile(validPath, []byte("[Interface]\nPrivateKey = "+key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"check-config", validPath}, &stdout, &stderr); exitCode != 0 {
		t.Fatalf("valid config failed: exit=%d stderr=%s", exitCode, stderr.String())
	}
	if stdout.String() != "valid\n" {
		t.Fatalf("unexpected output %q", stdout.String())
	}

	invalidPath := filepath.Join(directory, "invalid.conf")
	if err := os.WriteFile(invalidPath, []byte("[Interface]\nPrivateKey = sensitive-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if exitCode := run([]string{"check-config", invalidPath}, &stdout, &stderr); exitCode != 1 {
		t.Fatalf("invalid config exit code = %d, want 1", exitCode)
	}
	if strings.Contains(stderr.String(), "sensitive-value") {
		t.Fatalf("check-config leaked key material: %s", stderr.String())
	}
}

func TestCheckConfigRequiresPath(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"check-config"}, &stdout, &stderr); exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
}

func TestInvalidCommandReturnsUsageError(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"unknown"}, &stdout, &stderr); exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("usage is missing from stderr: %q", stderr.String())
	}
}
