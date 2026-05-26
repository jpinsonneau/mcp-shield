package handlers

import (
	"os"
	"strings"
)

const (
	envGatewayURL                = "OAUTH_AUTHORIZATION_SERVERS" // Use this to derive gateway URL
	envInspectorOrigin           = "INSPECTOR_ORIGIN"
	envOpenShiftOAuthTokenURL    = "OPENSHIFT_OAUTH_TOKEN_URL"
	envOAuthAuthorizationServers = "OAUTH_AUTHORIZATION_SERVERS"
	envOAuthClientID             = "OAUTH_CLIENT_ID"
	envOAuthRedirectURIs         = "OAUTH_REDIRECT_URIS" // Comma-separated list of additional redirect URIs
	// envDirectToolRouting: when false, tool calls always go to MCP_BACKEND_URL (e.g. mcp-gateway) instead of direct upstream hops.
	envDirectToolRouting = "MCP_SHIELD_DIRECT_TOOL_ROUTING"
)

// IsDirectToolRoutingEnabled returns whether tools/call may be routed directly to upstream MCP servers
// discovered from mcp-gateway. Default true for backward compatibility. Set MCP_SHIELD_DIRECT_TOOL_ROUTING
// to false, 0, or no to send all MCP traffic (including tools/call) through MCP_BACKEND_URL only.
func IsDirectToolRoutingEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(envDirectToolRouting)))
	switch v {
	case "", "1", "true", "t", "yes", "y", "on":
		return true
	case "0", "false", "f", "no", "n", "off":
		return false
	default:
		return true
	}
}
