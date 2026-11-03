package db

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeTaskAgentKey(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: ""},
		{in: "   ", want: ""},
		{in: "mobile", want: "mobile"},
		{in: "  miniprogram  ", want: "miniprogram"},
		{in: "web_shell2", want: "web_shell2"},
		{in: "Mobile", wantErr: true},
		{in: "1mobile", wantErr: true},
		{in: "mobile-app", wantErr: true},
		{in: "mobile app", wantErr: true},
		{in: strings.Repeat("a", MaxTaskAgentKeyRunes+1), wantErr: true},
	}
	for _, tc := range cases {
		got, err := NormalizeTaskAgentKey(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("NormalizeTaskAgentKey(%q) = %q, want error", tc.in, got)
			}
			if !errors.Is(err, ErrTaskAgentInvalid) {
				t.Fatalf("NormalizeTaskAgentKey(%q) error = %v, want ErrTaskAgentInvalid", tc.in, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeTaskAgentKey(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeTaskAgentKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAgentKeyString(t *testing.T) {
	if got := AgentKeyString(nil); got != "" {
		t.Fatalf("AgentKeyString(nil) = %q, want empty", got)
	}
	key := "mobile"
	if got := AgentKeyString(&key); got != "mobile" {
		t.Fatalf("AgentKeyString(&key) = %q, want mobile", got)
	}
}
