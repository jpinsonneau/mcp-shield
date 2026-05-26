package handlers

import "strings"

// isLoopbackRedirectURI is true for http redirect_uris we proxy via Shield's /oauth/callback
// (OpenShift OAuthClient cannot register every dynamic localhost port).
func isLoopbackRedirectURI(u string) bool {
	if u == "" {
		return false
	}
	return strings.HasPrefix(u, "http://localhost:") ||
		strings.HasPrefix(u, "http://127.0.0.1:")
}
