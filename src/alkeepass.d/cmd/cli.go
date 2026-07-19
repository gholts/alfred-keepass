package cmd

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"
)

type cliKeePassFile struct {
	Root struct {
		Group cliGroup `xml:"Group"`
	} `xml:"Root"`
}

type cliGroup struct {
	Name    string     `xml:"Name"`
	Groups  []cliGroup `xml:"Group"`
	Entries []cliEntry `xml:"Entry"`
}

type cliEntry struct {
	UUID     string        `xml:"UUID"`
	Times    cliEntryTimes `xml:"Times"`
	Strings  []cliString   `xml:"String"`
	Binaries []cliBinary   `xml:"Binary"`

	Path []string `xml:"-"`
}

type cliEntryTimes struct {
	Expires    string `xml:"Expires"`
	ExpiryTime string `xml:"ExpiryTime"`
}

type cliString struct {
	Key   string   `xml:"Key"`
	Value cliValue `xml:"Value"`
}

type cliValue struct {
	Content string `xml:",chardata"`
}

type cliBinary struct {
	Key string `xml:"Key"`
}

func searchWithCLI(kbdxpath string, query []string) (*AlfredJSON, error) {
	entries, err := loadEntriesWithCLI(kbdxpath)
	if err != nil {
		return nil, err
	}

	alf := readCLIEntries(entries, query)
	alf.Variables.Query = strings.Join(query, " ")
	return alf, nil
}

func getWithCLI(kbdxpath string, args []string) (*AlfredJSON, error) {
	entries, err := loadEntriesWithCLI(kbdxpath)
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("missing entry path")
	}

	entry := getCLIEntry(entries, args[0])
	if entry == nil {
		return nil, fmt.Errorf("entry not found: %s", args[0])
	}

	alf := AlfredJSON{}
	alf.Items = append(alf.Items, AlfredJSONItem{
		Uid:      "0",
		Title:    "Back",
		Subtitle: "Back to search",
		Arg:      "back",
	})
	addCLIFieldItem(&alf, entry, "2", "UserName", "UserName", "username", false)
	addCLIFieldItem(&alf, entry, "3", "Password", "Password", "password", true)
	addCLIFieldItem(&alf, entry, "4", "URL", "URL", "url", false)
	addCLIFieldItem(&alf, entry, "5", "Notes", "Notes", "notes", false)
	if entry.content("otp") != "" {
		alf.Items = append(alf.Items, AlfredJSONItem{
			Uid:      "6",
			Title:    "TOTP",
			Subtitle: "Generate TOTP token",
			Arg:      "otp",
		})
		alf.Items = append(alf.Items, AlfredJSONItem{
			Uid:      "7",
			Title:    "TOTP+Password",
			Subtitle: "Generate TOTP token + Password combined",
			Arg:      "otppass",
		})
	}

	uid := 8
	for _, item := range entry.Strings {
		switch item.Key {
		case "Title", "UserName", "Password", "URL", "Notes", "otp":
			continue
		}
		alf.Items = append(alf.Items, AlfredJSONItem{
			Uid:      fmt.Sprintf("%d", uid),
			Title:    item.Key,
			Subtitle: item.Value.Content,
			Arg:      item.Key,
		})
		uid++
	}

	for i, item := range entry.Binaries {
		if item.Key == "" {
			continue
		}
		alf.Items = append(alf.Items, AlfredJSONItem{
			Uid:       fmt.Sprintf("%d", i+100),
			Title:     fmt.Sprintf("Attached File (%d)", i+1),
			Subtitle:  item.Key,
			Arg:       "_file",
			Variables: map[string]string{"filename": item.Key},
		})
	}

	return &alf, nil
}

func loadEntriesWithCLI(kbdxpath string) ([]cliEntry, error) {
	dbPath, err := expandPath(kbdxpath)
	if err != nil {
		return nil, err
	}
	if dbPath == "" {
		return nil, fmt.Errorf("must configure keepassxc_db_path")
	}

	credArgs, password, err := cliCredentialArgs()
	if err != nil {
		return nil, err
	}

	args := append([]string{"export", "-q", "-f", "xml"}, credArgs...)
	args = append(args, dbPath)
	out, err := runKeepassXC(password, args...)
	if err != nil {
		return nil, err
	}

	var data cliKeePassFile
	if err := xml.Unmarshal(out, &data); err != nil {
		return nil, fmt.Errorf("parse keepassxc-cli XML export: %w", err)
	}

	entries := []cliEntry{}
	scanCLIGroup(data.Root.Group, nil, &entries)
	return entries, nil
}

func cliCredentialArgs() ([]string, string, error) {
	passwd := strings.TrimSpace(os.Getenv("keepassxc_master_password"))
	keyfilepath, err := expandPath(os.Getenv("keepassxc_keyfile_path"))
	if err != nil {
		return nil, "", err
	}
	if passwd == "" && keyfilepath == "" {
		return nil, "", fmt.Errorf("must configure keepassxc_master_password or keepassxc_keyfile_path")
	}

	args := []string{}
	if keyfilepath != "" {
		args = append(args, "-k", keyfilepath)
	}
	if passwd == "" {
		args = append(args, "--no-password")
	}
	return args, passwd, nil
}

func runKeepassXC(password string, args ...string) ([]byte, error) {
	cliPath, err := keepassXCPath()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(cliPath, args...)
	if password != "" {
		cmd.Stdin = strings.NewReader(password + "\n")
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("keepassxc-cli %s: %s", args[0], msg)
	}
	return out, nil
}

func keepassXCPath() (string, error) {
	candidates := []string{
		os.Getenv("keepassxc_cli_path"),
		"/opt/homebrew/bin/keepassxc-cli",
		"/usr/local/bin/keepassxc-cli",
		"/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli",
	}

	if path, err := exec.LookPath("keepassxc-cli"); err == nil {
		candidates = append(candidates, path)
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("keepassxc-cli not found")
}

func scanCLIGroup(group cliGroup, path []string, result *[]cliEntry) {
	nextPath := append(append([]string{}, path...), group.Name)
	for _, child := range group.Groups {
		scanCLIGroup(child, nextPath, result)
	}

	if len(nextPath) >= 2 {
		switch nextPath[1] {
		case "Backup", "Recycle Bin":
			return
		}
	}

	for _, entry := range group.Entries {
		title := entry.content("Title")
		if title == "" {
			continue
		}
		entry.Path = append(append([]string{}, nextPath...), title)
		*result = append(*result, entry)
	}
}

func readCLIEntries(entries []cliEntry, query []string) *AlfredJSON {
	alf := AlfredJSON{}
	for _, entry := range entries {
		path := strings.Join(entry.Path[1:], "/")
		matched := true
		for j := range query {
			if !strings.Contains(strings.ToLower(path), norm.NFC.String(strings.ToLower(query[j]))) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}

		item := AlfredJSONItem{
			Uid:      entry.UUID,
			Title:    entry.content("Title"),
			Subtitle: path,
			Mods: AlfredMods{
				Cmd:      AlfredModItem{Arg: path, Icon: &AlfredIcon{Path: "./icon-na.png"}},
				Alt:      AlfredModItem{Arg: path, Icon: &AlfredIcon{Path: "./icon-na.png"}},
				AltShift: AlfredModItem{Arg: path, Icon: &AlfredIcon{Path: "./icon-na.png"}},
				CmdAlt:   AlfredModItem{Arg: path, Icon: &AlfredIcon{Path: "./icon-na.png"}},
				Ctrl:     AlfredModItem{Arg: path, Valid: true},
			},
			Arg: path,
		}
		if entry.expired() {
			item.Title = "(Expired) " + item.Title
		}
		if entry.content("UserName") != "" {
			item.Mods.Cmd.Valid = true
			item.Mods.Cmd.Icon = nil
		}
		if entry.content("URL") != "" {
			item.Mods.Alt.Valid = true
			item.Mods.AltShift.Valid = true
			item.Mods.Alt.Icon = nil
			item.Mods.AltShift.Icon = nil
		}
		if entry.content("Notes") != "" {
			item.Mods.CmdAlt.Icon = nil
			item.Mods.CmdAlt.Valid = true
		}

		alf.Items = append(alf.Items, item)
	}
	return &alf
}

func getCLIEntry(entries []cliEntry, path string) *cliEntry {
	for i := range entries {
		if strings.Join(entries[i].Path[1:], "/") == path {
			return &entries[i]
		}
	}
	return nil
}

func addCLIFieldItem(alf *AlfredJSON, entry *cliEntry, uid, title, key, arg string, protected bool) {
	content := entry.content(key)
	if content == "" {
		return
	}
	subtitle := content
	if protected {
		subtitle = "*****"
	}
	alf.Items = append(alf.Items, AlfredJSONItem{
		Uid:      uid,
		Title:    title,
		Subtitle: subtitle,
		Arg:      arg,
	})
}

func (e cliEntry) content(key string) string {
	for _, item := range e.Strings {
		if item.Key == key {
			return item.Value.Content
		}
	}
	return ""
}

func (e cliEntry) expired() bool {
	if !strings.EqualFold(e.Times.Expires, "true") || e.Times.ExpiryTime == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, e.Times.ExpiryTime)
	return err == nil && t.Before(time.Now())
}
