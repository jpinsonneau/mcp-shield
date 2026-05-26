package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOAuthCallbackHandler_extractRedirectURIFromState(t *testing.T) {
	och := &OAuthCallbackHandler{Logger: discardLogger()}

	state := "orig-state|redirect_uri=" + "http%3A%2F%2Flocalhost%3A4000%2Fcallback"
	got := och.extractRedirectURIFromState(state, nil)
	if got != "http://localhost:4000/callback" {
		t.Fatalf("got %q", got)
	}
}

func TestOAuthCallbackHandler_extractRedirectURIFromState_queryFallback(t *testing.T) {
	och := &OAuthCallbackHandler{Logger: discardLogger()}
	q := httptest.NewRequest(http.MethodGet, "/cb", nil).URL.Query()
	q.Set("redirect_uri", "https://app.example/cb")
	got := och.extractRedirectURIFromState("plain", q)
	if got != "https://app.example/cb" {
		t.Fatalf("got %q", got)
	}
}

func TestOAuthCallbackHandler_extractOriginalState(t *testing.T) {
	och := &OAuthCallbackHandler{Logger: discardLogger()}
	got := och.extractOriginalState("orig|redirect_uri=http://x")
	if got != "orig" {
		t.Fatalf("got %q", got)
	}
	if och.extractOriginalState("") != "" {
		t.Fatal("empty state")
	}
}

func TestOAuthCallbackHandler_Handle_redirect(t *testing.T) {
	och := &OAuthCallbackHandler{Logger: discardLogger(), InspectorOrigin: "*"}
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=thecode&state="+
		"clientstate%7Credirect_uri%3Dhttp%253A%252F%252Flocalhost%253A1111%252Fcb", nil)
	rec := httptest.NewRecorder()
	och.Handle(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("want 302, got %d body=%s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc == "" || !strings.Contains(loc, "code=thecode") || !strings.Contains(loc, "localhost:1111") {
		t.Fatalf("unexpected Location: %q", loc)
	}
}

func TestOAuthCallbackHandler_Handle_oauthError(t *testing.T) {
	och := &OAuthCallbackHandler{Logger: discardLogger(), InspectorOrigin: "*"}
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?error=access_denied&error_description=nope", nil)
	rec := httptest.NewRecorder()
	och.Handle(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestOAuthCallbackHandler_Handle_missingCode(t *testing.T) {
	och := &OAuthCallbackHandler{Logger: discardLogger(), InspectorOrigin: "*"}
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?state=x", nil)
	rec := httptest.NewRecorder()
	och.Handle(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}
