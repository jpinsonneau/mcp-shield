package handlers

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/jpinsonn/mcp-shield/internal/tokenstore"
)

// MCPProxyHandler handles proxying requests to the MCP server
type MCPProxyHandler struct {
	Logger     *slog.Logger
	MCPBackend string                 // Backend MCP server URL (e.g., "http://localhost:8080")
	TokenStore *tokenstore.TokenStore // Token store for proxy token exchange
	httpClient *http.Client
}

// NewMCPProxyHandler creates a new MCPProxyHandler
func NewMCPProxyHandler(logger *slog.Logger, tokenStore *tokenstore.TokenStore) *MCPProxyHandler {
	mcpBackend := os.Getenv("MCP_BACKEND_URL")
	if mcpBackend == "" {
		mcpBackend = "http://localhost:8080" // Default to localhost:8080 in the same pod
		logger.Info("MCP_BACKEND_URL not set, using default", "backend", mcpBackend)
	}

	return &MCPProxyHandler{
		Logger:     logger,
		MCPBackend: mcpBackend,
		TokenStore: tokenStore,
		httpClient: &http.Client{
			// No timeout set - let the client handle timeouts
		},
	}
}

// Handle proxies requests to the MCP backend server
func (mph *MCPProxyHandler) Handle(w http.ResponseWriter, r *http.Request) {
	// Log Authorization header (without the token value for security)
	authHeader := r.Header.Get("Authorization")
	hasAuth := authHeader != ""
	authType := ""
	if hasAuth {
		// Log only the type, not the token
		authParts := strings.SplitN(authHeader, " ", 2)
		if len(authParts) > 0 {
			authType = authParts[0]
		}
	}
	mph.Logger.Info("Proxying MCP request", "method", r.Method, "path", r.URL.Path, "query", r.URL.RawQuery, "auth_type", authType, "has_auth", hasAuth)

	// Build backend URL
	backendURL, err := url.Parse(mph.MCPBackend)
	if err != nil {
		mph.Logger.Error("Invalid MCP backend URL", "error", err, "backend", mph.MCPBackend)
		http.Error(w, "Internal server error: invalid backend configuration", http.StatusInternalServerError)
		return
	}

	// Preserve the original path (e.g., /mcp)
	// If the request is to root (/), forward to /mcp on the backend
	if r.URL.Path == "/" {
		backendURL.Path = "/mcp"
	} else {
		backendURL.Path = r.URL.Path
	}
	backendURL.RawQuery = r.URL.RawQuery

	// Create a new request to the backend
	req, err := http.NewRequest(r.Method, backendURL.String(), r.Body)
	if err != nil {
		mph.Logger.Error("Failed to create backend request", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Handle Authorization header - exchange proxy token for real token
	if authHeader != "" {
		// Check if it's a Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			proxyToken := parts[1]

			// Try to exchange proxy token for real token
			realToken, found := mph.TokenStore.Get(proxyToken)
			if found {
				// Replace proxy token with real token
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", realToken))
				tokenPrefix := proxyToken
				if len(proxyToken) > 8 {
					tokenPrefix = proxyToken[:8] + "..."
				}
				mph.Logger.Debug("Exchanged proxy token for real token", "proxy_token_prefix", tokenPrefix)
			} else {
				// Proxy token not found or expired - forward as-is (will fail at MCP server)
				tokenPrefix := proxyToken
				if len(proxyToken) > 8 {
					tokenPrefix = proxyToken[:8] + "..."
				}
				mph.Logger.Warn("Proxy token not found or expired, forwarding as-is", "proxy_token_prefix", tokenPrefix)
				req.Header.Set("Authorization", authHeader)
			}
		} else {
			// Not a Bearer token, forward as-is
			req.Header.Set("Authorization", authHeader)
		}
	}

	// Copy other headers from the original request
	// Skip headers that should be set by the HTTP client
	skipHeaders := map[string]struct{}{
		"host":                {},
		"content-length":      {},
		"connection":          {},
		"transfer-encoding":   {},
		"upgrade":             {},
		"proxy-connection":    {},
		"proxy-authenticate":  {},
		"proxy-authorization": {},
		"authorization":       {}, // Already handled above
	}

	for k, v := range r.Header {
		lowerKey := strings.ToLower(k)
		if _, skip := skipHeaders[lowerKey]; !skip {
			for _, val := range v {
				req.Header.Add(k, val)
			}
		}
	}

	// Forward cookies explicitly (they might not be in the Header map)
	if r.Cookies() != nil {
		for _, cookie := range r.Cookies() {
			req.AddCookie(cookie)
		}
		mph.Logger.Debug("Forwarded cookies to MCP backend", "cookie_count", len(r.Cookies()))
	}

	// Forward the request to the backend
	resp, err := mph.httpClient.Do(req)
	if err != nil {
		mph.Logger.Error("Failed to forward request to MCP backend", "error", err, "backend", backendURL.String())
		http.Error(w, "Failed to connect to MCP server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers back to the client
	for k, v := range resp.Header {
		// Skip hop-by-hop headers
		lowerKey := strings.ToLower(k)
		if lowerKey == "connection" || lowerKey == "keep-alive" ||
			lowerKey == "proxy-authenticate" || lowerKey == "proxy-authorization" ||
			lowerKey == "te" || lowerKey == "trailers" || lowerKey == "transfer-encoding" ||
			lowerKey == "upgrade" {
			continue
		}
		// Log Set-Cookie headers for debugging session issues
		if lowerKey == "set-cookie" {
			mph.Logger.Debug("MCP backend set cookie", "cookie_count", len(v))
		}
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}

	// Log response status for debugging
	mph.Logger.Debug("MCP backend response", "status", resp.StatusCode, "status_text", resp.Status)

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	if _, err := io.Copy(w, resp.Body); err != nil {
		mph.Logger.Error("Failed to write response body", "error", err)
	}
}
