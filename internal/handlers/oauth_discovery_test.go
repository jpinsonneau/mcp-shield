package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOAuthDiscoveryHandler_HandleAuthorizationServer(t *testing.T) {
	odh := &OAuthDiscoveryHandler{
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		GatewayURL:      "https://shield.example.com",
		InspectorOrigin: "https://inspector.example",
		ClientID:        "cid",
		RedirectURIs:    []string{"https://shield.example.com/cb"},
	}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	odh.HandleAuthorizationServer(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var meta map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if meta["issuer"] != "https://shield.example.com" {
		t.Fatalf("issuer = %v", meta["issuer"])
	}
	if meta["token_endpoint"] != "https://shield.example.com/oauth/token" {
		t.Fatalf("token_endpoint = %v", meta["token_endpoint"])
	}
}

func TestOAuthDiscoveryHandler_HandleAuthorizationServer_notConfigured(t *testing.T) {
	odh := &OAuthDiscoveryHandler{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		GatewayURL: "",
	}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	odh.HandleAuthorizationServer(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", rec.Code)
	}
}

func TestOAuthDiscoveryHandler_HandleAuthorizationServer_options(t *testing.T) {
	odh := &OAuthDiscoveryHandler{
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		GatewayURL:      "https://x",
		InspectorOrigin: "*",
	}
	req := httptest.NewRequest(http.MethodOptions, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	odh.HandleAuthorizationServer(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", rec.Code)
	}
}

func TestOAuthDiscoveryHandler_HandleOAuthStart_intercepts127001(t *testing.T) {
	gw := "https://mcp-gateway.apps.cluster.example.com"
	odh := &OAuthDiscoveryHandler{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		GatewayURL: gw,
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "mcp-gateway")
	q.Set("redirect_uri", "http://127.0.0.1:4242/callback")
	q.Set("state", "abc")
	q.Set("code_challenge", "ch")
	q.Set("code_challenge_method", "S256")
	req := httptest.NewRequest(http.MethodGet, "/oauth2/start?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	odh.HandleOAuthStart(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("want 302, got %d body=%s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u.Host, "oauth-openshift") {
		t.Fatalf("expected redirect to openshift oauth, got %q", loc)
	}
	got := u.Query().Get("redirect_uri")
	want := gw + "/oauth/callback"
	if got != want {
		t.Fatalf("redirect_uri = %q, want %q", got, want)
	}
	st := u.Query().Get("state")
	if !strings.Contains(st, "|redirect_uri=") {
		t.Fatalf("state should embed original redirect_uri: %q", st)
	}
}
