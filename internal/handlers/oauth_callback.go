package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// OAuthCallbackHandler handles OAuth callbacks and redirects to the original redirect_uri
type OAuthCallbackHandler struct {
	Logger          *slog.Logger
	InspectorOrigin string
}

// NewOAuthCallbackHandler creates a new OAuthCallbackHandler
func NewOAuthCallbackHandler(logger *slog.Logger) *OAuthCallbackHandler {
	inspectorOrigin := os.Getenv(envInspectorOrigin)
	if inspectorOrigin == "" {
		inspectorOrigin = "*" // Default to allow all origins if not specified
	}

	return &OAuthCallbackHandler{
		Logger:          logger,
		InspectorOrigin: inspectorOrigin,
	}
}

// Handle processes OAuth callbacks from OpenShift and redirects to the original redirect_uri
// This allows us to use a fixed callback URL in the OAuthClient while supporting dynamic localhost ports
func (och *OAuthCallbackHandler) Handle(w http.ResponseWriter, r *http.Request) {
	och.Logger.Info("Handling OAuth callback", "method", r.Method, "path", r.URL.Path, "query", r.URL.RawQuery)

	// Handle OPTIONS preflight requests
	if r.Method == http.MethodOptions {
		och.addCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Extract query parameters
	queryParams := r.URL.Query()
	code := queryParams.Get("code")
	state := queryParams.Get("state")
	errorParam := queryParams.Get("error")
	errorDescription := queryParams.Get("error_description")

	// Check for errors from OpenShift
	if errorParam != "" {
		och.Logger.Error("OAuth callback error from OpenShift", "error", errorParam, "description", errorDescription, "state", state)
		http.Error(w, fmt.Sprintf("OAuth error: %s - %s", errorParam, errorDescription), http.StatusBadRequest)
		return
	}

	if code == "" {
		och.Logger.Error("OAuth callback missing authorization code")
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Extract the original redirect_uri from the state parameter
	// Format: state=<claude_state>|redirect_uri=<original_redirect_uri>
	originalRedirectURI := och.extractRedirectURIFromState(state, r.URL.Query())

	if originalRedirectURI == "" {
		och.Logger.Warn("Could not extract original redirect_uri from state, using default localhost callback")
		// Fallback: try to use a common localhost port or return an error
		// For now, we'll return an error and log the state for debugging
		och.Logger.Error("State parameter", "state", state, "all_params", r.URL.RawQuery)
		http.Error(w, "Could not determine redirect URI. Please ensure the OAuth flow includes the original redirect_uri in the state parameter.", http.StatusBadRequest)
		return
	}

	// Build the redirect URL with the code and state
	redirectURL, err := url.Parse(originalRedirectURI)
	if err != nil {
		och.Logger.Error("Invalid redirect URI", "error", err, "redirect_uri", originalRedirectURI)
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	// Add the code and state to the redirect URL
	redirectParams := redirectURL.Query()
	redirectParams.Set("code", code)
	if state != "" {
		// Preserve the original state (without our redirect_uri suffix)
		originalState := och.extractOriginalState(state)
		if originalState != "" {
			redirectParams.Set("state", originalState)
		} else {
			redirectParams.Set("state", state)
		}
	}
	redirectURL.RawQuery = redirectParams.Encode()

	och.Logger.Info("Redirecting to original redirect URI", "redirect_uri", redirectURL.String())
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// extractRedirectURIFromState extracts the original redirect_uri from the state parameter
// We encode it as: state=<original_state>|redirect_uri=<original_redirect_uri>
func (och *OAuthCallbackHandler) extractRedirectURIFromState(state string, queryParams url.Values) string {
	if state == "" {
		return ""
	}

	// Try to extract from state parameter format: <original_state>|redirect_uri=<uri>
	parts := strings.Split(state, "|redirect_uri=")
	if len(parts) == 2 {
		// URL decode the redirect_uri
		if decoded, err := url.QueryUnescape(parts[1]); err == nil {
			return decoded
		}
		return parts[1]
	}

	// Fallback: check if there's a redirect_uri in the query params (some OAuth servers preserve it)
	if redirectURI := queryParams.Get("redirect_uri"); redirectURI != "" {
		return redirectURI
	}

	return ""
}

// extractOriginalState extracts the original state (without our redirect_uri suffix)
func (och *OAuthCallbackHandler) extractOriginalState(state string) string {
	if state == "" {
		return ""
	}

	// If state contains our redirect_uri suffix, extract the original state
	parts := strings.Split(state, "|redirect_uri=")
	if len(parts) > 0 {
		return parts[0]
	}

	return state
}

// addCORSHeaders adds the necessary CORS headers to the response
func (och *OAuthCallbackHandler) addCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", och.InspectorOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, Origin, X-Requested-With, mcp-protocol-version")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "86400")
}
