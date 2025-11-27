package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// OAuthDiscoveryHandler handles OAuth discovery and registration endpoints
type OAuthDiscoveryHandler struct {
	Logger          *slog.Logger
	GatewayURL      string
	InspectorOrigin string
	ClientID        string
	RedirectURIs    []string
}

// NewOAuthDiscoveryHandler creates a new OAuth discovery handler
func NewOAuthDiscoveryHandler(logger *slog.Logger) *OAuthDiscoveryHandler {
	gatewayURL := getGatewayURL(logger)
	inspectorOrigin := getInspectorOrigin(logger)
	clientID := getClientID(logger)
	redirectURIs := getRedirectURIs(logger, gatewayURL, inspectorOrigin)

	return &OAuthDiscoveryHandler{
		Logger:          logger,
		GatewayURL:      gatewayURL,
		InspectorOrigin: inspectorOrigin,
		ClientID:        clientID,
		RedirectURIs:    redirectURIs,
	}
}

// OAuthAuthorizationServer represents the OAuth authorization server discovery response
type OAuthAuthorizationServer struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSUri                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// OAuthClientRegistration represents the OAuth client registration response
type OAuthClientRegistration struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ApplicationType         string   `json:"application_type"`
}

// HandleAuthorizationServer handles the /.well-known/oauth-authorization-server endpoint
func (odh *OAuthDiscoveryHandler) HandleAuthorizationServer(w http.ResponseWriter, r *http.Request) {
	odh.Logger.Info("Handling OAuth authorization server discovery request", "method", r.Method, "path", r.URL.Path)

	// Handle OPTIONS preflight requests
	if r.Method == http.MethodOptions {
		odh.addCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if odh.GatewayURL == "" {
		odh.Logger.Error("Gateway URL is not configured for OAuth discovery.")
		http.Error(w, "OAuth discovery not configured", http.StatusInternalServerError)
		return
	}

	// Construct the OAuth discovery metadata
	metadata := map[string]interface{}{
		"issuer":                                odh.GatewayURL,
		"authorization_endpoint":                fmt.Sprintf("%s/oauth2/start", odh.GatewayURL),
		"token_endpoint":                        fmt.Sprintf("%s/oauth/token", odh.GatewayURL),
		"jwks_uri":                              fmt.Sprintf("%s/oauth/jwks.json", odh.GatewayURL), // Placeholder, not implemented
		"registration_endpoint":                 fmt.Sprintf("%s/oauth/register", odh.GatewayURL),
		"response_types_supported":              []string{"code", "token"},
		"response_modes_supported":              []string{"query", "fragment", "form_post"},
		"grant_types_supported":                 []string{"authorization_code", "implicit"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"},
	}

	odh.addCORSHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		odh.Logger.Error("Failed to encode OAuth discovery metadata response", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// HandleClientRegistration handles the /oauth/register endpoint
func (odh *OAuthDiscoveryHandler) HandleClientRegistration(w http.ResponseWriter, r *http.Request) {
	odh.Logger.Info("Handling OAuth client registration request", "method", r.Method, "path", r.URL.Path)

	// Handle OPTIONS preflight requests
	if r.Method == http.MethodOptions {
		odh.addCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if odh.GatewayURL == "" {
		odh.Logger.Error("Gateway URL is not configured for OAuth client registration.")
		http.Error(w, "OAuth client registration not configured", http.StatusInternalServerError)
		return
	}

	// Return pre-configured OAuthClient information
	// OpenShift's official oauth-proxy does not support dynamic client registration,
	// so we return the details of the statically configured OAuthClient.
	clientInfo := map[string]interface{}{
		"client_id":                  odh.ClientID,
		"client_id_issued_at":        time.Now().Unix(),
		"redirect_uris":              odh.RedirectURIs,
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none", // Using PKCE, so no client_secret
		"application_type":           "web",
	}

	odh.addCORSHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(clientInfo); err != nil {
		odh.Logger.Error("Failed to encode OAuth client registration response", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// HandleOAuthStart redirects to the OpenShift OAuth authorization endpoint
func (odh *OAuthDiscoveryHandler) HandleOAuthStart(w http.ResponseWriter, r *http.Request) {
	odh.Logger.Info("Handling OAuth start request", "method", r.Method, "path", r.URL.Path, "query", r.URL.RawQuery)

	// Handle OPTIONS preflight requests
	if r.Method == http.MethodOptions {
		odh.addCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if odh.GatewayURL == "" {
		odh.Logger.Error("OAuth authorization server URL is not configured for OAuth start.")
		http.Error(w, "OAuth start not configured", http.StatusInternalServerError)
		return
	}

	// Extract cluster domain from OAUTH_AUTHORIZATION_SERVERS URL
	// URL format: https://<service-name>.apps.<cluster-domain>
	match := regexp.MustCompile(`https://[^.]*\.apps\.(.+)`).FindStringSubmatch(odh.GatewayURL)
	var clusterDomain string
	if len(match) > 1 {
		clusterDomain = match[1]
	} else {
		odh.Logger.Error("Could not extract cluster domain from OAuth authorization server URL", "url", odh.GatewayURL)
		http.Error(w, "Internal server error: could not determine cluster domain", http.StatusInternalServerError)
		return
	}

	openshiftOAuthURL := fmt.Sprintf("https://oauth-openshift.apps.%s/oauth/authorize", clusterDomain)

	// Parse existing query parameters
	queryParams := r.URL.Query()

	// Extract the original redirect_uri from the client request
	originalRedirectURI := queryParams.Get("redirect_uri")

	// Our fixed callback URL (registered in OAuthClient)
	fixedCallbackURL := fmt.Sprintf("%s/oauth/callback", odh.GatewayURL)

	// Check if PKCE is being used (code_challenge parameter present)
	usingPKCE := queryParams.Has("code_challenge")

	// If the redirect_uri is a localhost URL, we need to intercept it
	// Store the original redirect_uri in the state parameter and use our fixed callback
	if originalRedirectURI != "" && strings.HasPrefix(originalRedirectURI, "http://localhost:") {
		odh.Logger.Info("Intercepting localhost redirect URI", "original_redirect_uri", originalRedirectURI)

		// Append the original redirect_uri to the state parameter
		originalState := queryParams.Get("state")
		if originalState != "" {
			queryParams.Set("state", fmt.Sprintf("%s|redirect_uri=%s", originalState, url.QueryEscape(originalRedirectURI)))
		} else {
			queryParams.Set("state", fmt.Sprintf("|redirect_uri=%s", url.QueryEscape(originalRedirectURI)))
		}

		// Replace redirect_uri with our fixed callback URL
		queryParams.Set("redirect_uri", fixedCallbackURL)
	}

	var redirectURL string
	if usingPKCE {
		// When using PKCE, we need to be careful with encoding
		// Build the query string manually to preserve PKCE parameters
		redirectURL = fmt.Sprintf("%s?%s", openshiftOAuthURL, queryParams.Encode())
	} else {
		// For non-PKCE flows, we can modify parameters
		// Add resource parameter if not present
		if !queryParams.Has("resource") {
			queryParams.Set("resource", odh.GatewayURL)
		}

		// Add scope parameter if not present (OpenShift OAuth typically requires it)
		if !queryParams.Has("scope") || queryParams.Get("scope") == "" {
			queryParams.Set("scope", "user:info user:check-access")
		}

		// Build the redirect URL with all parameters
		redirectURL = fmt.Sprintf("%s?%s", openshiftOAuthURL, queryParams.Encode())
	}

	odh.Logger.Info("Redirecting to OpenShift OAuth authorization endpoint", "redirectURL", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// getGatewayURL retrieves the OAuth authorization server URL from OAUTH_AUTHORIZATION_SERVERS environment variable
// This should be the public URL where MCP Shield is accessible
func getGatewayURL(logger *slog.Logger) string {
	authServers := os.Getenv(envGatewayURL)
	if authServers == "" {
		logger.Warn("OAUTH_AUTHORIZATION_SERVERS environment variable is not set. OAuth discovery and registration may not work correctly.")
		return ""
	}
	// Assuming the first server in the comma-separated list is the primary one
	return strings.TrimSpace(strings.Split(authServers, ",")[0])
}

// getInspectorOrigin retrieves the inspector origin from INSPECTOR_ORIGIN environment variable
func getInspectorOrigin(logger *slog.Logger) string {
	inspectorOrigin := os.Getenv(envInspectorOrigin)
	if inspectorOrigin == "" {
		inspectorOrigin = "*" // Default to allow all origins if not specified
		logger.Warn("INSPECTOR_ORIGIN not set, defaulting to allow all origins for CORS. This is not recommended for production.")
	}
	return inspectorOrigin
}

// getClientID retrieves the OAuth client ID from OAUTH_CLIENT_ID environment variable
func getClientID(logger *slog.Logger) string {
	clientID := os.Getenv(envOAuthClientID)
	if clientID == "" {
		clientID = "prometheus-mcp-server" // Default fallback
		logger.Warn("OAUTH_CLIENT_ID not set, using default", "client_id", clientID)
	}
	return clientID
}

// getRedirectURIs builds the list of redirect URIs from environment variables
func getRedirectURIs(logger *slog.Logger, gatewayURL, inspectorOrigin string) []string {
	redirectURIs := []string{}

	// Always include the gateway callback
	if gatewayURL != "" {
		redirectURIs = append(redirectURIs, fmt.Sprintf("%s/oauth/callback", gatewayURL))
	}

	// Add inspector callbacks if inspector origin is set and not wildcard
	if inspectorOrigin != "" && inspectorOrigin != "*" {
		redirectURIs = append(redirectURIs,
			fmt.Sprintf("%s/oauth/callback/debug", inspectorOrigin),
			fmt.Sprintf("%s/oauth/callback", inspectorOrigin),
		)
	}

	// Add any additional redirect URIs from environment variable
	additionalURIs := os.Getenv(envOAuthRedirectURIs)
	if additionalURIs != "" {
		uris := strings.Split(additionalURIs, ",")
		for _, uri := range uris {
			trimmed := strings.TrimSpace(uri)
			if trimmed != "" {
				redirectURIs = append(redirectURIs, trimmed)
			}
		}
	}

	return redirectURIs
}

// addCORSHeaders adds the necessary CORS headers to the response
func (odh *OAuthDiscoveryHandler) addCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", odh.InspectorOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, Origin, X-Requested-With, mcp-protocol-version")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "86400")
}
