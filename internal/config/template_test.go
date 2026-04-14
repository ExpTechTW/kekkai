package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestRender_UsesCurrentVersionByDefault(t *testing.T) {
	out := Render(DefaultValues())
	want := fmt.Sprintf("version: %d", CurrentVersion)
	if !strings.Contains(out, want) {
		t.Fatalf("rendered template missing %q:\n%s", want, out)
	}
}

func TestValuesFromConfig_UsesCurrentVersionWhenUnset(t *testing.T) {
	cfg := &Config{
		Version: 0,
	}
	v := ValuesFromConfig(cfg)
	if v.Version != CurrentVersion {
		t.Fatalf("ValuesFromConfig version=%d, want %d", v.Version, CurrentVersion)
	}
}

func TestValuesFromConfig_DefaultsAutoUpdateDownloadToTrueWhenUnset(t *testing.T) {
	cfg := &Config{
		Update: UpdateConfig{
			AutoUpdateDownload: nil,
		},
	}
	v := ValuesFromConfig(cfg)
	if !v.AutoUpdateDownload {
		t.Fatalf("ValuesFromConfig AutoUpdateDownload=false, want true")
	}
}

func TestValuesFromConfig_PreservesAutoUpdateDownloadFalse(t *testing.T) {
	disabled := false
	cfg := &Config{
		Update: UpdateConfig{
			AutoUpdateDownload: &disabled,
		},
	}
	v := ValuesFromConfig(cfg)
	if v.AutoUpdateDownload {
		t.Fatalf("ValuesFromConfig AutoUpdateDownload=true, want false")
	}
}

func TestValuesFromConfig_NilConfigFallsBackToDefaults(t *testing.T) {
	v := ValuesFromConfig(nil)
	if v.Version != CurrentVersion {
		t.Fatalf("ValuesFromConfig(nil) version=%d, want %d", v.Version, CurrentVersion)
	}
	if !v.AutoUpdateDownload {
		t.Fatalf("ValuesFromConfig(nil) AutoUpdateDownload=false, want true")
	}
	if v.InterfaceXDPMode != DefaultXDPMode {
		t.Fatalf("ValuesFromConfig(nil) InterfaceXDPMode=%q, want %q", v.InterfaceXDPMode, DefaultXDPMode)
	}
	if v.UDPEphemeralMin != DefaultUDPEphemeralMin {
		t.Fatalf("ValuesFromConfig(nil) UDPEphemeralMin=%d, want %d", v.UDPEphemeralMin, DefaultUDPEphemeralMin)
	}
}

func TestValuesFromConfig_DefaultsNilBoolPointers(t *testing.T) {
	cfg := &Config{
		Security: SecurityConfig{
			EnforceSSHPrivate: nil,
		},
		Filter: FilterConfig{
			AllowICMP: nil,
			AllowARP:  nil,
		},
	}
	v := ValuesFromConfig(cfg)
	if !v.EnforceSSHPrivate {
		t.Fatalf("ValuesFromConfig EnforceSSHPrivate=false, want true")
	}
	if !v.AllowICMP {
		t.Fatalf("ValuesFromConfig AllowICMP=false, want true")
	}
	if !v.AllowARP {
		t.Fatalf("ValuesFromConfig AllowARP=false, want true")
	}
}
