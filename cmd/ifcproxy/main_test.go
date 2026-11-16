package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--version"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("exit code %d, stderr %q", code, errOut.String())
	}
	if !strings.HasPrefix(out.String(), "ifcproxy ") || strings.TrimSpace(out.String()) == "ifcproxy" {
		t.Fatalf("unexpected output %q", out.String())
	}
}

func TestVersionFromLdflags(t *testing.T) {
	old := version
	version = "v9.9.9"
	defer func() { version = old }()
	if got := versionString(); got != "v9.9.9" {
		t.Fatalf("versionString() = %q", got)
	}
}
