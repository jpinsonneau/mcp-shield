package handlers

import "testing"

func TestIsLoopbackRedirectURI(t *testing.T) {
	tests := []struct {
		u    string
		want bool
	}{
		{"", false},
		{"https://localhost:1/cb", false},
		{"http://localhost:5555/callback", true},
		{"http://127.0.0.1:5555/callback", true},
		{"http://[::1]:1/cb", false},
	}
	for _, tt := range tests {
		if got := isLoopbackRedirectURI(tt.u); got != tt.want {
			t.Errorf("isLoopbackRedirectURI(%q) = %v, want %v", tt.u, got, tt.want)
		}
	}
}
