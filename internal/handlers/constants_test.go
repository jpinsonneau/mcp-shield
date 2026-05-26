package handlers

import (
	"testing"
)

func TestIsDirectToolRoutingEnabled(t *testing.T) {
	cases := []struct {
		name  string
		env   string
		want  bool
		unset bool
	}{
		{name: "unset", unset: true, want: true},
		{name: "true", env: "true", want: true},
		{name: "TRUE", env: "TRUE", want: true},
		{name: "1", env: "1", want: true},
		{name: "yes", env: "yes", want: true},
		{name: "on", env: "on", want: true},
		{name: "false", env: "false", want: false},
		{name: "0", env: "0", want: false},
		{name: "no", env: "no", want: false},
		{name: "off", env: "off", want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.unset {
				t.Setenv(envDirectToolRouting, "")
			} else {
				t.Setenv(envDirectToolRouting, tc.env)
			}
			if got := IsDirectToolRoutingEnabled(); got != tc.want {
				t.Fatalf("IsDirectToolRoutingEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}
