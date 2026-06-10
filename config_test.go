package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeKey creates a readable dummy private key inside a temp dir and
// returns its path, so validation's ssh_key readability check passes for
// the cases that are meant to be valid.
func writeKey(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, []byte("dummy-key\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func intPtr(n int) *int { return &n }

// validJob returns a job that passes validation, using key as ssh_key.
func validJob(name, key string) job {
	return job{
		Name:       name,
		Local:      "/sources/" + name,
		RemoteHost: "root@192.168.1.87",
		RemotePath: "/srv/containers/" + name,
		SSHKey:     key,
	}
}

func TestValidate(t *testing.T) {
	key := writeKey(t)

	tests := []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{
			name: "valid minimal",
			cfg:  config{Jobs: []job{validJob("caddy", key)}},
		},
		{
			name: "valid with chown delete and excludes",
			cfg: config{Jobs: []job{{
				Name:       "caddy",
				Local:      "/sources/caddy",
				RemoteHost: "root@192.168.1.87",
				RemotePath: "/srv/containers/caddy",
				SSHKey:     key,
				RemoteUID:  intPtr(1000),
				RemoteGID:  intPtr(1000),
				Delete:     true,
				Excludes:   []string{"**/locks", "**/*.lock", "logs"},
			}}},
		},
		{
			name: "valid ipv6 host",
			cfg: config{Jobs: []job{{
				Name:       "v6",
				Local:      "/sources/v6",
				RemoteHost: "user@2001:db8::1",
				RemotePath: "/srv/v6",
				SSHKey:     key,
			}}},
		},
		{
			name:    "empty jobs",
			cfg:     config{Jobs: nil},
			wantErr: "jobs list is empty",
		},
		{
			name:    "missing name",
			cfg:     config{Jobs: []job{{Local: "/a", RemoteHost: "h", RemotePath: "/b", SSHKey: key}}},
			wantErr: "name is required",
		},
		{
			name:    "missing local",
			cfg:     config{Jobs: []job{{Name: "j", RemoteHost: "h", RemotePath: "/b", SSHKey: key}}},
			wantErr: "local is required",
		},
		{
			name:    "missing remote_host",
			cfg:     config{Jobs: []job{{Name: "j", Local: "/a", RemotePath: "/b", SSHKey: key}}},
			wantErr: "remote_host is required",
		},
		{
			name:    "missing remote_path",
			cfg:     config{Jobs: []job{{Name: "j", Local: "/a", RemoteHost: "h", SSHKey: key}}},
			wantErr: "remote_path is required",
		},
		{
			name:    "missing ssh_key",
			cfg:     config{Jobs: []job{{Name: "j", Local: "/a", RemoteHost: "h", RemotePath: "/b"}}},
			wantErr: "ssh_key is required",
		},
		{
			name: "duplicate names",
			cfg: config{Jobs: []job{
				validJob("dup", key),
				validJob("dup", key),
			}},
			wantErr: "duplicate name",
		},
		{
			name: "local not absolute",
			cfg: config{Jobs: []job{{
				Name: "j", Local: "relative/path", RemoteHost: "host",
				RemotePath: "/b", SSHKey: key,
			}}},
			wantErr: "must be absolute",
		},
		{
			name: "remote_path not absolute",
			cfg: config{Jobs: []job{{
				Name: "j", Local: "/a", RemoteHost: "host",
				RemotePath: "relative", SSHKey: key,
			}}},
			wantErr: "must be absolute",
		},
		{
			name: "remote_host with space",
			cfg: config{Jobs: []job{{
				Name: "j", Local: "/a", RemoteHost: "bad host",
				RemotePath: "/b", SSHKey: key,
			}}},
			wantErr: "remote_host",
		},
		{
			name: "remote_host with semicolon",
			cfg: config{Jobs: []job{{
				Name: "j", Local: "/a", RemoteHost: "host;rm -rf /",
				RemotePath: "/b", SSHKey: key,
			}}},
			wantErr: "remote_host",
		},
		{
			name: "dangerous char in local",
			cfg: config{Jobs: []job{{
				Name: "j", Local: "/a;rm", RemoteHost: "host",
				RemotePath: "/b", SSHKey: key,
			}}},
			wantErr: "forbidden characters",
		},
		{
			name: "dollar in remote_path",
			cfg: config{Jobs: []job{{
				Name: "j", Local: "/a", RemoteHost: "host",
				RemotePath: "/b/$(whoami)", SSHKey: key,
			}}},
			wantErr: "forbidden characters",
		},
		{
			name: "newline in local",
			cfg: config{Jobs: []job{{
				Name: "j", Local: "/a\nrm", RemoteHost: "host",
				RemotePath: "/b", SSHKey: key,
			}}},
			wantErr: "forbidden characters",
		},
		{
			name: "dangerous char in exclude",
			cfg: config{Jobs: []job{{
				Name: "j", Local: "/a", RemoteHost: "host",
				RemotePath: "/b", SSHKey: key,
				Excludes: []string{"good", "bad;evil"},
			}}},
			wantErr: "forbidden characters",
		},
		{
			name: "glob exclude is allowed",
			cfg: config{Jobs: []job{{
				Name: "j", Local: "/a", RemoteHost: "host",
				RemotePath: "/b", SSHKey: key,
				Excludes: []string{"**/*.lock", "**/locks"},
			}}},
		},
		{
			name: "ssh_key missing file",
			cfg: config{Jobs: []job{{
				Name: "j", Local: "/a", RemoteHost: "host",
				RemotePath: "/b", SSHKey: "/nonexistent/key",
			}}},
			wantErr: "not readable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validate() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validate() error = %q, want to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestHasShellMeta(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"plain path", "/sources/caddy", false},
		{"user at host", "root@192.168.1.87", false},
		{"glob exclude", "**/*.lock", false},
		{"ipv6 host", "2001:db8::1", false},
		{"dash and dot", "host-1.example.com", false},
		{"semicolon", "a;b", true},
		{"pipe", "a|b", true},
		{"ampersand", "a&b", true},
		{"dollar", "$(x)", true},
		{"backtick", "a`b`", true},
		{"newline", "a\nb", true},
		{"carriage return", "a\rb", true},
		{"tab", "a\tb", true},
		{"null", "a\x00b", true},
		{"redirect", "a>b", true},
		{"backslash", "a\\b", true},
		{"double quote", "a\"b", true},
		{"single quote", "a'b", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasShellMeta(tt.in); got != tt.want {
				t.Errorf("hasShellMeta(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseConfig(t *testing.T) {
	t.Parallel()
	doc := `
jobs:
  - name: caddy
    local: /sources/caddy
    remote_host: root@192.168.1.87
    remote_path: /srv/containers/caddy
    remote_uid: 1000
    remote_gid: 1000
    ssh_key: /keys/id_ed25519
    delete: true
    excludes: ["**/locks", "logs"]
`
	cfg, err := parseConfig([]byte(doc))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if len(cfg.Jobs) != 1 {
		t.Fatalf("len(Jobs) = %d, want 1", len(cfg.Jobs))
	}
	j := cfg.Jobs[0]
	if j.Name != "caddy" {
		t.Errorf("Name = %q, want caddy", j.Name)
	}
	if j.RemoteUID == nil || *j.RemoteUID != 1000 {
		t.Errorf("RemoteUID = %v, want 1000", j.RemoteUID)
	}
	if !j.Delete {
		t.Error("Delete = false, want true")
	}
	if len(j.Excludes) != 2 {
		t.Errorf("Excludes = %v, want 2 entries", j.Excludes)
	}
}

func TestParseConfigInvalidYAML(t *testing.T) {
	t.Parallel()
	_, err := parseConfig([]byte("jobs: [unterminated"))
	if err == nil {
		t.Fatal("parseConfig on malformed YAML: want error")
	}
	if !strings.Contains(err.Error(), "parse config") {
		t.Errorf("error = %q, want to contain 'parse config'", err)
	}
}

func TestLoadConfigEndToEnd(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(key, []byte("k\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	doc := "jobs:\n  - name: caddy\n    local: /sources/caddy\n" +
		"    remote_host: root@host\n    remote_path: /srv/caddy\n" +
		"    ssh_key: " + key + "\n"
	if err := os.WriteFile(cfgPath, []byte(doc), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CONFIG_PATH", cfgPath)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(cfg.Jobs) != 1 || cfg.Jobs[0].Name != "caddy" {
		t.Errorf("loadConfig = %+v, want one caddy job", cfg.Jobs)
	}
	// With SYNC_INTERVAL unset the built-in scheduler is enabled at the
	// default cadence.
	t.Setenv("SYNC_INTERVAL", "")
	cfg, err = loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !cfg.ScheduleEnabled {
		t.Error("ScheduleEnabled = false, want true by default")
	}
	if cfg.Interval != defaultInterval {
		t.Errorf("Interval = %v, want default %v", cfg.Interval, defaultInterval)
	}
}

func TestLoadInterval(t *testing.T) {
	tests := []struct {
		name         string
		env          string
		wantInterval time.Duration
		wantEnabled  bool
	}{
		{"duration", "30m", 30 * time.Minute, true},
		{"hour duration", "1h", time.Hour, true},
		{"off", "off", defaultInterval, false},
		{"off uppercase", "OFF", defaultInterval, false},
		{"disabled", "disabled", defaultInterval, false},
		{"disabled mixed case", "Disabled", defaultInterval, false},
		{"zero", "0", defaultInterval, false},
		{"zero seconds", "0s", defaultInterval, false},
		{"unset defaults to enabled", "", defaultInterval, true},
		{"unparseable falls back enabled", "not-a-duration", defaultInterval, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SYNC_INTERVAL", tt.env)
			interval, enabled := loadInterval()
			if enabled != tt.wantEnabled {
				t.Errorf("loadInterval() enabled = %v, want %v", enabled, tt.wantEnabled)
			}
			if interval != tt.wantInterval {
				t.Errorf("loadInterval() interval = %v, want %v", interval, tt.wantInterval)
			}
		})
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	t.Setenv("CONFIG_PATH", filepath.Join(t.TempDir(), "absent.yaml"))
	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig on missing file: want error")
	}
}

func TestLoadSyncTimeout(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		t.Setenv("SYNC_TIMEOUT", "")
		if got := loadSyncTimeout(); got != defaultSyncTimeout {
			t.Errorf("loadSyncTimeout() = %v, want %v", got, defaultSyncTimeout)
		}
	})
	t.Run("parsed value", func(t *testing.T) {
		t.Setenv("SYNC_TIMEOUT", "30m")
		if got := loadSyncTimeout(); got.String() != "30m0s" {
			t.Errorf("loadSyncTimeout() = %v, want 30m0s", got)
		}
	})
	t.Run("default on garbage", func(t *testing.T) {
		t.Setenv("SYNC_TIMEOUT", "not-a-duration")
		if got := loadSyncTimeout(); got != defaultSyncTimeout {
			t.Errorf("loadSyncTimeout() = %v, want %v", got, defaultSyncTimeout)
		}
	})
	t.Run("default on non-positive", func(t *testing.T) {
		t.Setenv("SYNC_TIMEOUT", "-5m")
		if got := loadSyncTimeout(); got != defaultSyncTimeout {
			t.Errorf("loadSyncTimeout() = %v, want %v", got, defaultSyncTimeout)
		}
	})
}

func TestGetEnv(t *testing.T) {
	t.Setenv("TEST_RSYNC_ENV", "value")
	if got := getEnv("TEST_RSYNC_ENV", "fallback"); got != "value" {
		t.Errorf("getEnv = %q, want value", got)
	}
	t.Setenv("TEST_RSYNC_ENV", "")
	if got := getEnv("TEST_RSYNC_ENV", "fallback"); got != "fallback" {
		t.Errorf("getEnv = %q, want fallback", got)
	}
}
