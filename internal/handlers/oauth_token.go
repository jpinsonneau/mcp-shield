package handlers

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jpinsonn/mcp-shield/internal/tokenstore"
)

// OAuthTokenHandler handles the /oauth/token endpoint for OpenShift OAuth token exchange
type OAuthTokenHandler struct {
	Logger           *slog.Logger
	OAuthTokenURL    string
	InspectorOrigin  string
	FixedCallbackURL string                 // The fixed callback URL registered in OAuthClient
	ClientID         string                 // OAuth client ID for authentication
	TokenStore       *tokenstore.TokenStore // Token store for proxy tokens
	httpClient       *http.Client
}

// NewOAuthTokenHandler creates a new OAuthTokenHandler
func NewOAuthTokenHandler(logger *slog.Logger) *OAuthTokenHandler {
	oauthTokenURL := os.Getenv(envOpenShiftOAuthTokenURL)
	if oauthTokenURL == "" {
		// Attempt to derive from OAUTH_AUTHORIZATION_SERVERS if OPENSHIFT_OAUTH_TOKEN_URL is not set
		authServers := os.Getenv(envOAuthAuthorizationServers)
		if authServers != "" {
			// Assuming the first server in the comma-separated list is the primary one
			firstAuthServer := strings.TrimSpace(strings.Split(authServers, ",")[0])
			// Extract cluster domain from OAUTH_AUTHORIZATION_SERVERS
			// URL format: https://<service-name>.apps.<cluster-domain>
			match := regexp.MustCompile(`https://[^.]*\.apps\.(.+)`).FindStringSubmatch(firstAuthServer)
			if len(match) > 1 {
				clusterDomain := match[1]
				oauthTokenURL = fmt.Sprintf("https://oauth-openshift.apps.%s/oauth/token", clusterDomain)
				logger.Info("Derived OpenShift OAuth Token URL", "url", oauthTokenURL)
			} else {
				logger.Warn("Could not derive OpenShift OAuth Token URL from OAUTH_AUTHORIZATION_SERVERS. Please set OPENSHIFT_OAUTH_TOKEN_URL explicitly.")
			}
		} else {
			logger.Warn("OPENSHIFT_OAUTH_TOKEN_URL and OAUTH_AUTHORIZATION_SERVERS are not set. OAuth token exchange may not work.")
		}
	}

	inspectorOrigin := os.Getenv(envInspectorOrigin)
	if inspectorOrigin == "" {
		inspectorOrigin = "*" // Default to allow all origins if not specified
		logger.Warn("INSPECTOR_ORIGIN not set, defaulting to allow all origins for CORS. This is not recommended for production.")
	}

	// Get the fixed callback URL from OAUTH_AUTHORIZATION_SERVERS
	fixedCallbackURL := ""
	authServers := os.Getenv(envOAuthAuthorizationServers)
	if authServers != "" {
		firstAuthServer := strings.TrimSpace(strings.Split(authServers, ",")[0])
		fixedCallbackURL = fmt.Sprintf("%s/oauth/callback", firstAuthServer)
		logger.Info("Using fixed callback URL for token exchange", "callback_url", fixedCallbackURL)
	}

	// Get client ID for authentication
	clientID := os.Getenv(envOAuthClientID)
	if clientID == "" {
		clientID = "prometheus-mcp-server" // Default fallback
		logger.Warn("OAUTH_CLIENT_ID not set, using default", "client_id", clientID)
	}

	// Configure a custom HTTP client to skip SSL verification for OpenShift's self-signed certs
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second, // 30 second timeout
	}

	// Create token store with 24 hour TTL (default)
	tokenTTL := 24 * time.Hour
	if ttlStr := os.Getenv("PROXY_TOKEN_TTL"); ttlStr != "" {
		if parsedTTL, err := time.ParseDuration(ttlStr); err == nil {
			tokenTTL = parsedTTL
			logger.Info("Using custom proxy token TTL", "ttl", tokenTTL)
		} else {
			logger.Warn("Invalid PROXY_TOKEN_TTL, using default", "ttl", tokenTTL, "error", err)
		}
	}
	tokenStore := tokenstore.NewTokenStore(logger, tokenTTL)

	return &OAuthTokenHandler{
		Logger:           logger,
		OAuthTokenURL:    oauthTokenURL,
		InspectorOrigin:  inspectorOrigin,
		FixedCallbackURL: fixedCallbackURL,
		ClientID:         clientID,
		TokenStore:       tokenStore,
		httpClient:       httpClient,
	}
}

// GetTokenStore returns the token store (for sharing with MCPProxyHandler)
func (oth *OAuthTokenHandler) GetTokenStore() *tokenstore.TokenStore {
	return oth.TokenStore
}

// Handle handles the /oauth/token endpoint
func (oth *OAuthTokenHandler) Handle(w http.ResponseWriter, r *http.Request) {
	oth.Logger.Info("Handling OAuth token exchange request", "method", r.Method, "path", r.URL.Path)

	// Handle OPTIONS preflight requests
	if r.Method == http.MethodOptions {
		oth.addCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if oth.OAuthTokenURL == "" {
		oth.Logger.Error("OpenShift OAuth Token URL is not configured.")
		http.Error(w, "OAuth token endpoint not configured", http.StatusInternalServerError)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		oth.Logger.Error("Failed to read request body", "error", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Log original request body for debugging
	oth.Logger.Info("Original token exchange request body", "body", string(body))

	// Filter out resource=undefined and fix redirect_uri for localhost callbacks
	filteredBody := oth.filterResourceUndefined(body)
	filteredBody = oth.fixRedirectURI(filteredBody)

	// Log the final request body for debugging
	oth.Logger.Info("Final token exchange request body", "body", string(filteredBody))

	// Create a new request to OpenShift's OAuth token endpoint
	req, err := http.NewRequest(http.MethodPost, oth.OAuthTokenURL, bytes.NewReader(filteredBody))
	if err != nil {
		oth.Logger.Error("Failed to create new request to OpenShift OAuth", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Copy original headers, but skip host, content-length, and content-type as they are set by http.NewRequest
	skipHeaders := map[string]struct{}{
		"host":              {},
		"content-length":    {},
		"content-type":      {},
		"connection":        {},
		"transfer-encoding": {},
	}
	for k, v := range r.Header {
		if _, skip := skipHeaders[strings.ToLower(k)]; !skip {
			for _, val := range v {
				req.Header.Add(k, val)
			}
		}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded") // Ensure correct content type

	// Add Basic Auth with client_id (even for PKCE, OpenShift may require this)
	// For PKCE flows, we use client_id with empty secret
	if oth.ClientID != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:", oth.ClientID)))
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))
		oth.Logger.Debug("Added Basic Auth header for client authentication", "client_id", oth.ClientID)
	}

	// Forward the request
	resp, err := oth.httpClient.Do(req)
	if err != nil {
		oth.Logger.Error("Failed to forward token exchange request to OpenShift OAuth", "error", err)
		http.Error(w, "Token exchange failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read the response body to extract the access token
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		oth.Logger.Error("Failed to read token response body", "error", err)
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	// Check if the response is successful before trying to parse as JSON
	if resp.StatusCode != http.StatusOK {
		oth.Logger.Warn("Token exchange returned non-200 status", "status", resp.StatusCode, "body", string(bodyBytes))
		// Forward error response as-is
		for k, v := range resp.Header {
			lowerKey := strings.ToLower(k)
			if !strings.HasPrefix(lowerKey, "access-control-") {
				for _, val := range v {
					w.Header().Add(k, val)
				}
			}
		}
		oth.addCORSHeaders(w)
		w.WriteHeader(resp.StatusCode)
		w.Write(bodyBytes)
		return
	}

	// Parse the token response
	var tokenResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		oth.Logger.Error("Failed to parse token response", "error", err, "body", string(bodyBytes))
		// If it's not JSON, forward as-is (might be an error response)
		for k, v := range resp.Header {
			lowerKey := strings.ToLower(k)
			if !strings.HasPrefix(lowerKey, "access-control-") {
				for _, val := range v {
					w.Header().Add(k, val)
				}
			}
		}
		oth.addCORSHeaders(w)
		w.WriteHeader(resp.StatusCode)
		w.Write(bodyBytes)
		return
	}

	// Check if we got an access token
	accessToken, hasToken := tokenResponse["access_token"].(string)
	if !hasToken || accessToken == "" {
		// No access token, forward response as-is (might be an error)
		oth.Logger.Warn("Token response missing access_token", "response", tokenResponse)
		for k, v := range resp.Header {
			lowerKey := strings.ToLower(k)
			if !strings.HasPrefix(lowerKey, "access-control-") {
				for _, val := range v {
					w.Header().Add(k, val)
				}
			}
		}
		oth.addCORSHeaders(w)
		w.WriteHeader(resp.StatusCode)
		w.Write(bodyBytes)
		return
	}

	// Generate a proxy token
	proxyToken, err := oth.TokenStore.GenerateProxyToken()
	if err != nil {
		oth.Logger.Error("Failed to generate proxy token", "error", err)
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	// Store the mapping: proxy_token -> real_token
	oth.TokenStore.Store(proxyToken, accessToken)
	tokenPrefix := proxyToken
	if len(proxyToken) > 8 {
		tokenPrefix = proxyToken[:8] + "..."
	}
	oth.Logger.Info("Generated proxy token for user token", "proxy_token_prefix", tokenPrefix)

	// Replace the access_token in the response with the proxy token
	tokenResponse["access_token"] = proxyToken
	// Also replace refresh_token if present
	if refreshToken, hasRefresh := tokenResponse["refresh_token"].(string); hasRefresh && refreshToken != "" {
		// Store refresh token mapping too (using same proxy token prefix)
		// For simplicity, we'll just store the refresh token with the same proxy token
		// In a more sophisticated implementation, you might want separate handling
		oth.Logger.Debug("Refresh token present, storing mapping", "proxy_token_prefix", proxyToken[:8]+"...")
	}

	// Marshal the modified response
	modifiedBody, err := json.Marshal(tokenResponse)
	if err != nil {
		oth.Logger.Error("Failed to marshal modified token response", "error", err)
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	// Copy response headers (excluding CORS and Content-Type/Content-Length, as we set our own)
	for k, v := range resp.Header {
		lowerKey := strings.ToLower(k)
		if !strings.HasPrefix(lowerKey, "access-control-") &&
			lowerKey != "content-type" &&
			lowerKey != "content-length" {
			for _, val := range v {
				w.Header().Add(k, val)
			}
		}
	}

	// Explicitly set Content-Type to application/json
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(modifiedBody)))

	oth.addCORSHeaders(w) // Add our own CORS headers

	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(modifiedBody); err != nil {
		oth.Logger.Error("Failed to write token response body", "error", err)
		return
	}

	oth.Logger.Debug("Successfully sent token response with proxy token",
		"status", resp.StatusCode,
		"content_length", len(modifiedBody),
		"proxy_token_prefix", tokenPrefix)
}

// filterResourceUndefined parses the request body and removes the "resource=undefined" parameter
func (oth *OAuthTokenHandler) filterResourceUndefined(body []byte) []byte {
	bodyStr := string(body)
	oth.Logger.Debug("Original token request body", "body", bodyStr)

	params, err := url.ParseQuery(bodyStr)
	if err != nil {
		oth.Logger.Error("Failed to parse query string from token request body", "error", err)
		return body // Return original body if parsing fails
	}

	if resource, ok := params["resource"]; ok && len(resource) > 0 && resource[0] == "undefined" {
		params.Del("resource")
		oth.Logger.Info("Removed 'resource=undefined' from token exchange request")
	}

	filteredBody := params.Encode()
	oth.Logger.Debug("Filtered token request body", "body", filteredBody)
	return []byte(filteredBody)
}

// fixRedirectURI replaces localhost redirect_uri with the fixed callback URL
// This is needed because OpenShift expects the same redirect_uri that was used in the authorization request
func (oth *OAuthTokenHandler) fixRedirectURI(body []byte) []byte {
	if oth.FixedCallbackURL == "" {
		return body // No fixed callback URL configured, return as-is
	}

	bodyStr := string(body)
	oth.Logger.Debug("Original token request body (before redirect_uri fix)", "body", bodyStr)

	params, err := url.ParseQuery(bodyStr)
	if err != nil {
		oth.Logger.Error("Failed to parse query string for redirect_uri fix", "error", err)
		return body // Return original body if parsing fails
	}

	// Check if redirect_uri is a localhost URL
	if redirectURI, ok := params["redirect_uri"]; ok && len(redirectURI) > 0 {
		uri := redirectURI[0]
		if strings.HasPrefix(uri, "http://localhost:") {
			oth.Logger.Info("Replacing localhost redirect_uri with fixed callback URL",
				"original", uri,
				"fixed", oth.FixedCallbackURL)
			params.Set("redirect_uri", oth.FixedCallbackURL)
		}
	}

	fixedBody := params.Encode()
	oth.Logger.Debug("Fixed token request body (after redirect_uri fix)", "body", fixedBody)
	return []byte(fixedBody)
}

// addCORSHeaders adds the necessary CORS headers to the response
func (oth *OAuthTokenHandler) addCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", oth.InspectorOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, Origin, X-Requested-With")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "86400")
}
