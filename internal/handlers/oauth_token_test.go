package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jpinsonn/mcp-shield/internal/tokenstore"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestOAuthTokenHandler_filterResourceUndefined(t *testing.T) {
	oth := &OAuthTokenHandler{Logger: discardLogger()}
	in := []byte("grant_type=authorization_code&code=abc&resource=undefined&client_id=x")
	out := oth.filterResourceUndefined(in)
	if strings.Contains(string(out), "resource=") {
		t.Fatalf("resource should be removed: %s", out)
	}
	if !strings.Contains(string(out), "grant_type=authorization_code") {
		t.Fatalf("expected grant_type preserved: %s", out)
	}
}

func TestOAuthTokenHandler_filterResourceUndefined_nonUndefined(t *testing.T) {
	oth := &OAuthTokenHandler{Logger: discardLogger()}
	in := []byte("grant_type=authorization_code&resource=https%3A%2F%2Fapi")
	out := oth.filterResourceUndefined(in)
	if !strings.Contains(string(out), "resource=") {
		t.Fatalf("non-undefined resource should remain: %s", out)
	}
}

func TestOAuthTokenHandler_fixRedirectURI(t *testing.T) {
	oth := &OAuthTokenHandler{
		Logger:           discardLogger(),
		FixedCallbackURL: "https://shield.example/oauth/callback",
	}
	in := []byte("grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A9876%2Fcb&code=x")
	out := oth.fixRedirectURI(in)
	if !strings.Contains(string(out), "redirect_uri=https%3A%2F%2Fshield.example%2Foauth%2Fcallback") {
		t.Fatalf("expected fixed redirect_uri in encoded form, got: %s", out)
	}
}

func TestOAuthTokenHandler_fixRedirectURI_127001(t *testing.T) {
	oth := &OAuthTokenHandler{
		Logger:           discardLogger(),
		FixedCallbackURL: "https://shield.example/oauth/callback",
	}
	in := []byte("grant_type=authorization_code&redirect_uri=http%3A%2F%2F127.0.0.1%3A9876%2Fcb&code=x")
	out := oth.fixRedirectURI(in)
	if !strings.Contains(string(out), "redirect_uri=https%3A%2F%2Fshield.example%2Foauth%2Fcallback") {
		t.Fatalf("expected fixed redirect_uri in encoded form, got: %s", out)
	}
}

func TestOAuthTokenHandler_fixRedirectURI_noFixedURL(t *testing.T) {
	oth := &OAuthTokenHandler{Logger: discardLogger(), FixedCallbackURL: ""}
	in := []byte("redirect_uri=http%3A%2F%2Flocalhost%3A1%2Fcb")
	out := oth.fixRedirectURI(in)
	if string(out) != string(in) {
		t.Fatalf("expected unchanged body: %s", out)
	}
}

func TestOAuthTokenHandler_Handle_tokenExchange_proxyResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Basic ") {
			t.Errorf("expected Basic auth, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "openshift-real-token",
			"token_type":   "Bearer",
		})
	}))
	defer upstream.Close()

	ts := tokenstore.NewTokenStore(discardLogger(), time.Hour)
	defer ts.Stop()

	oth := &OAuthTokenHandler{
		Logger:           discardLogger(),
		OAuthTokenURL:    upstream.URL,
		InspectorOrigin:  "*",
		FixedCallbackURL: "https://shield.example/oauth/callback",
		ClientID:         "testclient",
		TokenStore:       ts,
		httpClient:       upstream.Client(),
	}

	body := "grant_type=authorization_code&code=abc&redirect_uri=http%3A%2F%2Flocalhost%3A1%2Fcb&resource=undefined"
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	oth.Handle(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	proxy, _ := resp["access_token"].(string)
	if proxy == "" || proxy == "openshift-real-token" {
		t.Fatalf("expected proxy token in response, got %q", proxy)
	}
	real, ok := ts.Get(proxy)
	if !ok || real != "openshift-real-token" {
		t.Fatalf("store Get = %q, %v; want openshift-real-token, true", real, ok)
	}
}

func TestOAuthTokenHandler_Handle_noTokenURL(t *testing.T) {
	oth := &OAuthTokenHandler{
		Logger:        discardLogger(),
		OAuthTokenURL: "",
		TokenStore:    tokenstore.NewTokenStore(discardLogger(), time.Hour),
		httpClient:    http.DefaultClient,
	}
	defer oth.TokenStore.Stop()

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewReader([]byte("x=1")))
	rec := httptest.NewRecorder()
	oth.Handle(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", rec.Code)
	}
}

func TestOAuthTokenHandler_Handle_methodNotAllowed(t *testing.T) {
	oth := &OAuthTokenHandler{
		Logger:        discardLogger(),
		OAuthTokenURL: "http://example.com",
		TokenStore:    tokenstore.NewTokenStore(discardLogger(), time.Hour),
		httpClient:    http.DefaultClient,
	}
	defer oth.TokenStore.Stop()

	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	rec := httptest.NewRecorder()
	oth.Handle(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rec.Code)
	}
}

func TestNewOAuthTokenHandler_derivesInClusterTokenURL(t *testing.T) {
	t.Setenv("OPENSHIFT_OAUTH_TOKEN_URL", "")
	t.Setenv("OAUTH_AUTHORIZATION_SERVERS", "https://mcp-gateway.apps.rosa.example.p3.openshiftapps.com")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	h := NewOAuthTokenHandler(discardLogger())
	defer h.TokenStore.Stop()
	if h.OAuthTokenURL != openShiftOAuthTokenURLInCluster {
		t.Fatalf("OAuthTokenURL=%q want %q", h.OAuthTokenURL, openShiftOAuthTokenURLInCluster)
	}
}

func TestNewOAuthTokenHandler_derivesPublicTokenURLOutsideCluster(t *testing.T) {
	t.Setenv("OPENSHIFT_OAUTH_TOKEN_URL", "")
	t.Setenv("OAUTH_AUTHORIZATION_SERVERS", "https://mcp-gateway.apps.rosa.example.p3.openshiftapps.com")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	h := NewOAuthTokenHandler(discardLogger())
	defer h.TokenStore.Stop()
	want := "https://oauth-openshift.apps.rosa.example.p3.openshiftapps.com/oauth/token"
	if h.OAuthTokenURL != want {
		t.Fatalf("OAuthTokenURL=%q want %q", h.OAuthTokenURL, want)
	}
}
