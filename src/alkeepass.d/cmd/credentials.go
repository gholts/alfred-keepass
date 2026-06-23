package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tobischo/gokeepasslib/v3"
)

func databasePathFromEnv() string {
	return os.Getenv("keepassxc_db_path")
}

func credentialsFromEnv() (*gokeepasslib.DBCredentials, error) {
	passwd := strings.TrimSpace(os.Getenv("keepassxc_master_password"))
	keyfilepath, err := expandPath(os.Getenv("keepassxc_keyfile_path"))
	if err != nil {
		return nil, err
	}

	switch {
	case passwd != "" && keyfilepath != "":
		cred, err := gokeepasslib.NewPasswordAndKeyCredentials(passwd, keyfilepath)
		if err != nil {
			return nil, fmt.Errorf("load key file: %w", err)
		}
		return cred, nil
	case passwd != "":
		return gokeepasslib.NewPasswordCredentials(passwd), nil
	case keyfilepath != "":
		cred, err := gokeepasslib.NewKeyCredentials(keyfilepath)
		if err != nil {
			return nil, fmt.Errorf("load key file: %w", err)
		}
		return cred, nil
	default:
		return nil, fmt.Errorf("must configure keepassxc_master_password or keepassxc_keyfile_path")
	}
}

func openDatabase(path string) (*os.File, error) {
	expanded, err := expandPath(path)
	if err != nil {
		return nil, err
	}
	if expanded == "" {
		return nil, fmt.Errorf("must configure keepassxc_db_path")
	}
	return os.Open(expanded)
}

func expandPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}
