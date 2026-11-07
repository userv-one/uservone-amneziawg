package main

import (
	"bytes"
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
