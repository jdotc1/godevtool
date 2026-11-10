package environ

import (
	"runtime"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	info := Detect(nil)

	if info.GoVersion == "" {
		t.Error("GoVersion empty")
	}
	if info.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %q, want %q", info.GoVersion, runtime.Version())
	}
	if info.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", info.OS, runtime.GOOS)
	}
	if info.Arch != runtime.GOARCH {
		t.Errorf("Arch = %q, want %q", info.Arch, runtime.GOARCH)
	}
	if info.NumCPU == 0 {
		t.Error("NumCPU = 0")
	}
	if info.PID == 0 {
		t.Error("PID = 0")
	}
	if info.WorkDir == "" {
		t.Error("WorkDir empty")
	}
	if info.StartTime.IsZero() {
		t.Error("StartTime is zero")
	}
}

func TestDetectEnvFilter(t *testing.T) {
	// custom filter that only includes HOME
	info := Detect(func(key string) bool {
		return key == "HOME"
	})

	for k := range info.EnvVars {
		if k != "HOME" {
			t.Errorf("unexpected env var %q", k)
		}
	}
}

func TestDetectDefaultFilter(t *testing.T) {
	info := Detect(nil)
	// Sensitive variables may appear, but their values must never appear.
	for k, value := range info.EnvVars {
		if strings.Contains(strings.ToUpper(k), "PASSWORD") ||
			strings.Contains(strings.ToUpper(k), "SECRET") ||
			strings.Contains(strings.ToUpper(k), "TOKEN") {
			if value != "********" {
				t.Errorf("sensitive value leaked for %q", k)
			}
		}
	}
}

func TestDefaultEnvFilter(t *testing.T) {
	for _, tt := range []struct {
		key  string
		want bool
	}{
		{"GOOS", true}, {"GOMAXPROCS", true}, {"GOMEMLIMIT", true},
		{"PORT", true}, {"APP_FEATURE_FLAG", true}, {"SERVICE_REGION", true},
		{"GOOGLE_API_KEY", false}, {"GOTCHA_TOKEN", false}, {"CUSTOM_SECRET", false},
	} {
		if got := defaultEnvFilter(tt.key); got != tt.want {
			t.Errorf("defaultEnvFilter(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestDetectRedactsSecretValues(t *testing.T) {
	for _, key := range []string{
		"APP_DB_PASSWORD", "SERVICE_TOKEN", "APP_PASSWD", "APP_SECRET",
		"APP_API_KEY", "APP_CREDENTIAL", "APP_PRIVATE_SETTING",
	} {
		t.Setenv(key, "example-secret-value")
	}
	t.Setenv("GOOGLE_API_KEY", "example-google-secret")
	t.Setenv("GOOS", "linux")
	t.Setenv("GOMAXPROCS", "4")
	t.Setenv("PORT", "8080")
	t.Setenv("APP_FEATURE_FLAG", "enabled")

	info := Detect(nil)
	if _, exists := info.EnvVars["GOOGLE_API_KEY"]; exists {
		t.Error("GOOGLE_API_KEY must not pass the default filter")
	}
	for _, key := range []string{
		"APP_DB_PASSWORD", "SERVICE_TOKEN", "APP_PASSWD", "APP_SECRET",
		"APP_API_KEY", "APP_CREDENTIAL", "APP_PRIVATE_SETTING",
	} {
		if got := info.EnvVars[key]; got != "********" {
			t.Errorf("value for %q = %q, want redaction", key, got)
		}
	}
	for key, want := range map[string]string{
		"GOOS": "linux", "GOMAXPROCS": "4", "PORT": "8080", "APP_FEATURE_FLAG": "enabled",
	} {
		if got := info.EnvVars[key]; got != want {
			t.Errorf("value for %q = %q, want %q", key, got, want)
		}
	}

	// Custom filters must not provide a route around value redaction.
	custom := Detect(func(string) bool { return true })
	if got := custom.EnvVars["GOOGLE_API_KEY"]; got != "********" {
		t.Errorf("custom filter exposed GOOGLE_API_KEY: %q", got)
	}
}

func TestUptime(t *testing.T) {
	info := Detect(nil)
	uptime := info.Uptime()
	if uptime <= 0 {
		t.Errorf("uptime = %v, expected > 0", uptime)
	}
	s := info.UptimeStr()
	if s == "" {
		t.Error("UptimeStr empty")
	}
}

func TestFormatInfo(t *testing.T) {
	info := Detect(nil)
	output := FormatInfo(info, false)

	checks := []string{"Go Version", "OS / Arch", "CPUs", "PID"}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected %q in output:\n%s", check, output)
		}
	}
}

func TestBuildInfo(t *testing.T) {
	info := Detect(nil)
	// Build info may or may not be available depending on how tests are run
	if info.BuildInfo != nil {
		if info.BuildInfo.GoVersion == "" {
			t.Error("BuildInfo.GoVersion empty")
		}
	}
}
