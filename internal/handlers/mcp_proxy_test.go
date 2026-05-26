package handlers

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jpinsonn/mcp-shield/internal/tokenstore"
)

func TestMCPProxyHandler_forwardsToolsCallThroughBackend_withProxyExchange(t *testing.T) {
	var sawAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			t.Errorf("path %s", r.URL.Path)
		}
		sawAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer backend.Close()

	t.Setenv("MCP_BACKEND_URL", backend.URL)
	t.Setenv("MCP_BACKEND_PATH", "/mcp")
	t.Setenv("MCP_SHIELD_DIRECT_TOOL_ROUTING", "false")

	ts := tokenstore.NewTokenStore(discardLogger(), time.Hour)
	defer ts.Stop()
	ts.Store("proxy-xyz", "real-openshift-token")

	h := NewMCPProxyHandler(discardLogger(), ts)
	h.ToolRouter = nil
	h.GatewayDiscoverer = nil

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"prom_test","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer proxy-xyz")
	rec := httptest.NewRecorder()

	h.Handle(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
	}
	if sawAuth != "Bearer real-openshift-token" {
		t.Fatalf("backend Authorization = %q", sawAuth)
	}
}

func TestMCPProxyHandler_preservesBearerWhenNotProxy(t *testing.T) {
	var sawAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer backend.Close()

	t.Setenv("MCP_BACKEND_URL", backend.URL)
	t.Setenv("MCP_BACKEND_PATH", "/mcp")
	t.Setenv("MCP_SHIELD_DIRECT_TOOL_ROUTING", "false")

	ts := tokenstore.NewTokenStore(discardLogger(), time.Hour)
	defer ts.Stop()

	h := NewMCPProxyHandler(discardLogger(), ts)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
	)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer already-real")
	rec := httptest.NewRecorder()
	h.Handle(rec, req)
	if sawAuth != "Bearer already-real" {
		t.Fatalf("got %q", sawAuth)
	}
}

func TestMCPProxyHandler_toolsList_injectsSessionWhenMissing(t *testing.T) {
	var body string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer backend.Close()

	t.Setenv("MCP_BACKEND_URL", backend.URL)
	t.Setenv("MCP_BACKEND_PATH", "/mcp")
	t.Setenv("MCP_SHIELD_DIRECT_TOOL_ROUTING", "false")

	ts := tokenstore.NewTokenStore(discardLogger(), time.Hour)
	defer ts.Stop()
	h := NewMCPProxyHandler(discardLogger(), ts)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
	)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Handle(rec, req)
	if !strings.Contains(body, "sessionId") {
		t.Fatalf("expected sessionId injected: %s", body)
	}
}
