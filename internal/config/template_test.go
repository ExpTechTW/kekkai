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
