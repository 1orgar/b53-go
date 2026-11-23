package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1orgar/b53-go"
)

func emptyEnv(string) string { return "" }

func TestCLIGenerateSaltStdoutAndFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"generate-salt"}, &stdout, &stderr, emptyEnv)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	outSalt := strings.TrimSpace(stdout.String())
	if len(outSalt) != 64 {
		t.Fatalf("len(outSalt) = %d, want 64", len(outSalt))
	}
	if _, err := hex.DecodeString(outSalt); err != nil {
		t.Fatalf("invalid hex salt: %v", err)
	}

	outFile := filepath.Join(t.TempDir(), "salt.txt")
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"keygen", "--bytes", "16", "--out", outFile}, &stdout, &stderr, emptyEnv)
	if code != 0 {
		t.Fatalf("keygen exit code = %d, stderr = %q", code, stderr.String())
	}
	raw, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	saved := strings.TrimSpace(string(raw))
	if len(saved) != 32 {
		t.Fatalf("len(saved) = %d, want 32", len(saved))
	}
	if !strings.Contains(stdout.String(), saved) {
		t.Fatalf("stdout %q does not contain saved salt %q", stdout.String(), saved)
	}
}

func TestCLIEncryptDecryptRoundtripAndQuiet(t *testing.T) {
	salt := strings.Repeat("ab", 32)
	saltFile := filepath.Join(t.TempDir(), "secret.salt")
	if err := os.WriteFile(saltFile, []byte(salt+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"encrypt", "1011001011", "--salt-file", saltFile, "--count", "3"}, &stdout, &stderr, emptyEnv)
	if code != 0 {
		t.Fatalf("encrypt exit = %d, stderr = %q", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d output lines, want 4: %q", len(lines), stdout.String())
	}
	parts := strings.SplitN(lines[1], " ", 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected count line %q", lines[1])
	}
	firstVal := parts[1]

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"decrypt", firstVal, "--salt", salt}, &stdout, &stderr, emptyEnv)
	if code != 0 {
		t.Fatalf("decrypt exit = %d, stderr = %q", code, stderr.String())
	}
	decOut := stdout.String()
	if !strings.Contains(decOut, "Restored length: 10") || !strings.Contains(decOut, "1011001011") {
		t.Fatalf("unexpected decrypt output: %q", decOut)
	}

	// Test B53_SALT env var, flags before/after positional, and -q/--quiet.
	envWithSalt := func(k string) string {
		if k == "B53_SALT" {
			return salt
		}
		return ""
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"encrypt", "true,false,true", "-q"}, &stdout, &stderr, envWithSalt)
	if code != 0 {
		t.Fatalf("quiet encrypt exit = %d, stderr = %q", code, stderr.String())
	}
	quietVal := strings.TrimSpace(stdout.String())

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"decrypt", "--quiet", quietVal}, &stdout, &stderr, envWithSalt)
	if code != 0 {
		t.Fatalf("quiet decrypt exit = %d, stderr = %q", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "101" {
		t.Fatalf("quiet decrypt = %q, want %q", stdout.String(), "101")
	}

	// Decrypt a Python-generated ciphertext via CLI.
	stdout.Reset()
	stderr.Reset()
	code = run(
		[]string{"decrypt", "0.29004509923272503", "--salt", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "-q"},
		&stdout,
		&stderr,
		emptyEnv,
	)
	if code != 0 || strings.TrimSpace(stdout.String()) != "1011001011" {
		t.Fatalf("CLI decrypt Python vector = (%d, %q, %q)", code, stdout.String(), stderr.String())
	}
}

func TestCLIInterleavedAndTerminatorFlags(t *testing.T) {
	// Literal "--" passed as --salt value followed by positional bits and -q flag.
	var stdout, stderr bytes.Buffer
	code := run([]string{"encrypt", "--salt", "--", "1010", "-q"}, &stdout, &stderr, emptyEnv)
	if code != 0 {
		t.Fatalf("encrypt with -- salt failed: code=%d stderr=%q", code, stderr.String())
	}
	val := strings.TrimSpace(stdout.String())

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"decrypt", val, "--salt", "--", "-q"}, &stdout, &stderr, emptyEnv)
	if code != 0 || strings.TrimSpace(stdout.String()) != "1010" {
		t.Fatalf("decrypt with -- salt failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}

	// Explicit "--" terminator followed by extra positional should fail positional count check, not parse "--salt" as flag.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"encrypt", "--", "1010", "--salt"}, &stdout, &stderr, emptyEnv)
	if code != 2 {
		t.Fatalf("expected exit 2 for extra positional after --, got %d", code)
	}
}

func TestCLIErrorHandlingAndVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run([]string{"--version"}, &stdout, &stderr, emptyEnv); code != 0 || strings.TrimSpace(stdout.String()) != "b53 "+b53.Version {
		t.Fatalf("--version = (%d, %q, %q)", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"--help"}, &stdout, &stderr, emptyEnv); code != 0 || !strings.Contains(stdout.String(), "Usage: b53") {
		t.Fatalf("--help = (%d, %q, %q)", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run(nil, &stdout, &stderr, emptyEnv); code != 2 {
		t.Fatalf("empty args exit = %d, want 2", code)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"encrypt", "101"}, &stdout, &stderr, emptyEnv); code != 1 || !strings.Contains(stderr.String(), "salt is required") {
		t.Fatalf("missing salt = (%d, %q)", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"encrypt", "101", "--salt", "abc", "--count", "0"}, &stdout, &stderr, emptyEnv); code != 1 || !strings.Contains(stderr.String(), "--count") {
		t.Fatalf("bad count = (%d, %q)", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"decrypt", "not-a-float", "--salt", "abc"}, &stdout, &stderr, emptyEnv); code != 1 || !strings.Contains(stderr.String(), "Error:") {
		t.Fatalf("bad float = (%d, %q)", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"encrypt", "101", "--salt", "a", "--salt-file", "b"}, &stdout, &stderr, emptyEnv); code != 1 || !strings.Contains(stderr.String(), "not both") {
		t.Fatalf("both salt flags = (%d, %q)", code, stderr.String())
	}

	// Explicit empty --salt "" should fail even if B53_SALT is set.
	stdout.Reset()
	stderr.Reset()
	envSet := func(string) string { return "fallback" }
	if code := run([]string{"encrypt", "101", "--salt", ""}, &stdout, &stderr, envSet); code != 1 {
		t.Fatalf("explicit empty --salt exit = %d, want 1", code)
	}
}

func TestCLIDeriveSaltAndSerializeDeserialize(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// Test derive-salt with fast scrypt parameters matching Python golden output.
	code := run(
		[]string{"derive-salt", "my-password", "--context", "tenant-a", "--n", "16", "--r", "1", "--p", "1"},
		&stdout,
		&stderr,
		emptyEnv,
	)
	if code != 0 {
		t.Fatalf("derive-salt exit = %d, stderr = %q", code, stderr.String())
	}
	derivedSalt := strings.TrimSpace(stdout.String())
	const wantDerived = "c0ecc4f8084ce34736771e417c5ee34f85f2b2ff51b794c43dc9e4c73765b52a"
	if derivedSalt != wantDerived {
		t.Fatalf("derive-salt = %q, want %q", derivedSalt, wantDerived)
	}

	// Test serialize -> deserialize roundtrip via CLI.
	bits := "10110010110101010101110011001"
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"serialize", bits, "--salt", derivedSalt, "--min-size", "8", "-q"}, &stdout, &stderr, emptyEnv)
	if code != 0 {
		t.Fatalf("serialize exit = %d, stderr = %q", code, stderr.String())
	}
	chunkLines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(chunkLines) != (len(bits)/8)+1 {
		t.Fatalf("got %d chunks, want %d", len(chunkLines), (len(bits)/8)+1)
	}

	stdout.Reset()
	stderr.Reset()
	code = run(
		[]string{"deserialize", strings.Join(chunkLines, ","), "--salt", derivedSalt, "-q"},
		&stdout,
		&stderr,
		emptyEnv,
	)
	if code != 0 || strings.TrimSpace(stdout.String()) != bits {
		t.Fatalf("deserialize = (%d, %q, %q), want %q", code, stdout.String(), stderr.String(), bits)
	}

	// Empty array serialize -> deserialize roundtrip.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"serialize", "", "--salt", derivedSalt, "-q"}, &stdout, &stderr, emptyEnv)
	if code != 0 || strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("serialize empty = (%d, %q, %q)", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"deserialize", "", "--salt", derivedSalt, "-q"}, &stdout, &stderr, emptyEnv)
	if code != 0 || strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("deserialize empty = (%d, %q, %q)", code, stdout.String(), stderr.String())
	}
}
