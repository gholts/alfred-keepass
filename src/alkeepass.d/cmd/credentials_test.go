package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		"":                 "",
		"relative.key":     "relative.key",
		"/tmp/private.key": "/tmp/private.key",
		"~":                home,
		"~/private.key":    filepath.Join(home, "private.key"),
	}

	for input, want := range tests {
		got, err := expandPath(input)
		if err != nil {
			t.Fatalf("expandPath(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("expandPath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCredentialsFromEnvPasswordOnly(t *testing.T) {
	setEnv(t, "keepassxc_master_password", "Abc12345")
	setEnv(t, "keepassxc_keyfile_path", "")

	cred, err := credentialsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.Passphrase) == 0 {
		t.Fatal("expected passphrase")
	}
	if len(cred.Key) != 0 {
		t.Fatal("did not expect key")
	}
}

func TestCredentialsFromEnvPasswordAndKeyFile(t *testing.T) {
	keyFile := writeTestKeyFile(t)
	setEnv(t, "keepassxc_master_password", "Abc12345")
	setEnv(t, "keepassxc_keyfile_path", keyFile)

	cred, err := credentialsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.Passphrase) == 0 {
		t.Fatal("expected passphrase")
	}
	if len(cred.Key) == 0 {
		t.Fatal("expected key")
	}
}

func TestCredentialsFromEnvKeyFileOnly(t *testing.T) {
	keyFile := writeTestKeyFile(t)
	setEnv(t, "keepassxc_master_password", "")
	setEnv(t, "keepassxc_keyfile_path", keyFile)

	cred, err := credentialsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.Passphrase) != 0 {
		t.Fatal("did not expect passphrase")
	}
	if len(cred.Key) == 0 {
		t.Fatal("expected key")
	}
}

func TestCredentialsFromEnvRequiresPasswordOrKeyFile(t *testing.T) {
	setEnv(t, "keepassxc_master_password", "")
	setEnv(t, "keepassxc_keyfile_path", "")

	if _, err := credentialsFromEnv(); err == nil {
		t.Fatal("expected error")
	}
}

func writeTestKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.key")
	if err := os.WriteFile(path, []byte("12345678901234567890123456789012"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func setEnv(t *testing.T, key, value string) {
	t.Helper()
	old, ok := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if ok {
			_ = os.Setenv(key, old)
			return
		}
		_ = os.Unsetenv(key)
	})
}
