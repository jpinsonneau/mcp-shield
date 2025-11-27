package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	Logger      *slog.Logger
	MCPBackend  string                 // Backend MCP server URL (e.g., "http://localhost:8080")
	BackendPath string                 // Backend path to forward to (e.g., "/mcp" or "/stream")
	TokenStore  *tokenstore.TokenStore // Token store for proxy token exchange
	httpClient  *http.Client
}

// NewMCPProxyHandler creates a new MCPProxyHandler
func NewMCPProxyHandler(logger *slog.Logger, tokenStore *tokenstore.TokenStore) *MCPProxyHandler {
	mcpBackend := os.Getenv("MCP_BACKEND_URL")
	if mcpBackend == "" {
		mcpBackend = "http://localhost:8080" // Default to localhost:8080 in the same pod
		logger.Info("MCP_BACKEND_URL not set, using default", "backend", mcpBackend)
	}

	// Get backend path from environment variable, default to /mcp for Prometheus MCP server
	backendPath := os.Getenv("MCP_BACKEND_PATH")
	if backendPath == "" {
		backendPath = "/mcp" // Default to /mcp for Prometheus MCP server compatibility
		logger.Info("MCP_BACKEND_PATH not set, using default", "path", backendPath)
	} else {
		logger.Info("Using configured MCP_BACKEND_PATH", "path", backendPath)
	}

	return &MCPProxyHandler{
		Logger:      logger,
		MCPBackend:  mcpBackend,
		BackendPath: backendPath,
		TokenStore:  tokenStore,
		httpClient:  &http.Client{
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
	// If the request is to root (/), forward to the configured backend path
	// For Prometheus MCP server: use /mcp
	// For Loki MCP server: use /stream
	if r.URL.Path == "/" || r.URL.Path == "/mcp" || r.URL.Path == "/mcp/" {
		backendURL.Path = mph.BackendPath
		mph.Logger.Debug("Forwarding to configured backend path", "original_path", r.URL.Path, "backend_path", mph.BackendPath)
	} else {
		backendURL.Path = r.URL.Path
	}
	backendURL.RawQuery = r.URL.RawQuery

	// Read request body to potentially modify JSON-RPC requests
	var requestBody []byte
	if r.Body != nil {
		requestBody, err = io.ReadAll(r.Body)
		if err != nil {
			mph.Logger.Error("Failed to read request body", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		r.Body.Close()
	}

	// Try to parse as JSON-RPC and inject sessionId if missing (for Loki MCP server)
	var modifiedBody []byte = requestBody
	if len(requestBody) > 0 {
		contentType := r.Header.Get("Content-Type")
		// Only try to parse JSON if Content-Type suggests it's JSON
		if strings.Contains(strings.ToLower(contentType), "application/json") || contentType == "" {
			var jsonRPC map[string]interface{}
			if err := json.Unmarshal(requestBody, &jsonRPC); err == nil {
				// Check if it's a JSON-RPC request (has jsonrpc field)
				if _, isJSONRPC := jsonRPC["jsonrpc"]; isJSONRPC {
					// Check if sessionId is missing (check both root level and params level)
					hasSessionID := false
					var sessionID string

					// Check root level
					if sid, ok := jsonRPC["sessionId"].(string); ok && sid != "" {
						hasSessionID = true
						sessionID = sid
					}

					// Check params level
					if !hasSessionID {
						if params, ok := jsonRPC["params"].(map[string]interface{}); ok {
							if sid, ok := params["sessionId"].(string); ok && sid != "" {
								hasSessionID = true
								sessionID = sid
							}
						}
					}

					if !hasSessionID {
						// Generate a sessionId - try to get from cookie first, otherwise generate a new one
						if sessionCookie, err := r.Cookie("mcp-session-id"); err == nil && sessionCookie.Value != "" {
							sessionID = sessionCookie.Value
							mph.Logger.Info("Using sessionId from cookie", "sessionId", sessionID)
						} else {
							// Generate a UUID-like sessionId (16 random bytes = 32 hex chars)
							randomBytes := make([]byte, 16)
							if _, err := rand.Read(randomBytes); err == nil {
								sessionID = hex.EncodeToString(randomBytes)
							} else {
								// Fallback if crypto/rand fails
								sessionID = fmt.Sprintf("%x", len(requestBody)+len(authHeader))
								if authHeader != "" {
									parts := strings.SplitN(authHeader, " ", 2)
									if len(parts) == 2 && len(parts[1]) > 8 {
										sessionID = parts[1][:8] + "-" + sessionID
									}
								}
							}
							mph.Logger.Info("Generated new sessionId", "sessionId", sessionID)
						}

						// Inject sessionId in both params and root level (Loki MCP server might check both)
						jsonRPC["sessionId"] = sessionID
						if params, ok := jsonRPC["params"].(map[string]interface{}); ok {
							params["sessionId"] = sessionID
							mph.Logger.Info("Injected sessionId into both params and root level", "sessionId", sessionID)
						} else {
							mph.Logger.Info("Injected sessionId into root level (params not found)", "sessionId", sessionID)
						}

						// Re-marshal the modified JSON
						modifiedBody, err = json.Marshal(jsonRPC)
						if err != nil {
							mph.Logger.Warn("Failed to inject sessionId, forwarding original body", "error", err)
							modifiedBody = requestBody
						} else {
							// Log the actual JSON being sent for debugging
							previewLen := 500
							if len(modifiedBody) < previewLen {
								previewLen = len(modifiedBody)
							}
							// Also verify the sessionId is actually in the marshaled JSON
							var verifyJSON map[string]interface{}
							if err := json.Unmarshal(modifiedBody, &verifyJSON); err == nil {
								hasRootSessionID := false
								hasParamsSessionID := false
								if sid, ok := verifyJSON["sessionId"].(string); ok && sid != "" {
									hasRootSessionID = true
								}
								if params, ok := verifyJSON["params"].(map[string]interface{}); ok {
									if sid, ok := params["sessionId"].(string); ok && sid != "" {
										hasParamsSessionID = true
									}
								}
								mph.Logger.Info("Injected sessionId into JSON-RPC request",
									"sessionId", sessionID,
									"body_length", len(modifiedBody),
									"has_root_sessionId", hasRootSessionID,
									"has_params_sessionId", hasParamsSessionID,
									"body_preview", string(modifiedBody[:previewLen]))
							} else {
								mph.Logger.Warn("Failed to verify injected sessionId", "error", err)
							}
						}
					} else {
						mph.Logger.Debug("JSON-RPC request already has sessionId")
					}
				} else {
					mph.Logger.Debug("Request is JSON but not JSON-RPC (no jsonrpc field)")
				}
			} else {
				previewLen := 100
				if len(requestBody) < previewLen {
					previewLen = len(requestBody)
				}
				mph.Logger.Debug("Failed to parse request body as JSON", "error", err, "content_type", contentType, "body_preview", string(requestBody[:previewLen]))
			}
		} else {
			mph.Logger.Debug("Skipping JSON parsing, Content-Type is not JSON", "content_type", contentType)
		}
	} else {
		mph.Logger.Debug("Request body is empty, skipping sessionId injection")
	}

	// Create a new request to the backend with modified body
	req, err := http.NewRequest(r.Method, backendURL.String(), bytes.NewReader(modifiedBody))
	if err != nil {
		mph.Logger.Error("Failed to create backend request", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set Content-Length header if body was modified
	if len(modifiedBody) != len(requestBody) {
		req.ContentLength = int64(len(modifiedBody))
		mph.Logger.Debug("Updated Content-Length after body modification", "old_length", len(requestBody), "new_length", len(modifiedBody))
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
