package main

import (
	"testing"
	"time"
)

func TestParseProcUptime(t *testing.T) {
	tests := []struct {
		content string
		want    time.Duration
		wantErr bool
	}{
		{"20900.50 41234.10\n", 20900500 * time.Millisecond, false}, // first field only
		{"123.00", 123 * time.Second, false},
		{"  45.25  9.9 ", 45250 * time.Millisecond, false}, // leading/trailing space
		{"", 0, true},
		{"notanumber 1.0", 0, true},
	}
	for _, tt := range tests {
		got, err := parseProcUptime(tt.content)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseProcUptime(%q) = %v, want error", tt.content, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseProcUptime(%q) error: %v", tt.content, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseProcUptime(%q) = %v, want %v", tt.content, got, tt.want)
		}
	}
}
