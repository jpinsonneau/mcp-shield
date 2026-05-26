//go:build e2e

// Package e2e runs subprocess tests against the real mcp-shield binary.
// OpenShift OAuth is simulated with httptest servers (token endpoint + MCP backend).
//
// Run: make test-e2e   or   go test -tags=e2e -v ./tests/e2e/... -timeout=120s
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found from cwd %s", dir)
		}
		dir = parent
	}
}

func buildShieldBinary(t *testing.T) string {
	t.Helper()
	root := findRepoRoot(t)
	out := filepath.Join(t.TempDir(), "mcp-shield")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/mcp-shield")
	cmd.Dir = root
	outb, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, outb)
	}
	return out
}

func waitHealthy(t *testing.T, base string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	u := strings.TrimSuffix(base, "/") + "/healthz"
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return
		}
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		select {
		case <-ctx.Done():
			t.Fatalf("shield did not become healthy: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func startFakeOpenShiftToken(t *testing.T, realAccessToken string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "resource=undefined") {
			t.Errorf("upstream token request still contains resource=undefined: %q", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": realAccessToken,
			"token_type":   "Bearer",
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func startFakeMCPBackend(t *testing.T, wantRealToken *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		if wantRealToken != nil {
			*wantRealToken = r.Header.Get("Authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func startShieldProcess(t *testing.T, bin, listenAddr string, env []string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(bin, "-listen", listenAddr, "-log-level", "error")
	cmd.Env = env
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("start shield: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd
}

// TestShieldDiscoveryOAuthTokenAndMCP runs mcp-shield as a subprocess with fake OpenShift token
// and fake MCP backends (httptest). Exercises: /healthz, OAuth discovery, /oauth/token (proxy),
// POST /mcp (proxy token -> real token).
func TestShieldDiscoveryOAuthTokenAndMCP(t *testing.T) {
	const realOpenShiftLikeToken = "e2e-real-access-token-xyz"

	tokenSrv := startFakeOpenShiftToken(t, realOpenShiftLikeToken)
	var gotAuth string
	mcpSrv := startFakeMCPBackend(t, &gotAuth)

	bin := buildShieldBinary(t)
	listenAddr := freeListenAddr(t)
	publicURL := "http://" + listenAddr
	env := append(os.Environ(),
		"OPENSHIFT_OAUTH_TOKEN_URL="+tokenSrv.URL,
		"OAUTH_AUTHORIZATION_SERVERS="+publicURL,
		"MCP_BACKEND_URL="+mcpSrv.URL,
		"MCP_BACKEND_PATH=/mcp",
		"MCP_SHIELD_DIRECT_TOOL_ROUTING=false",
		"INSPECTOR_ORIGIN=*",
		"OAUTH_CLIENT_ID=e2e-client",
	)
	time.Sleep(50 * time.Millisecond)
	startShieldProcess(t, bin, listenAddr, env)
	waitHealthy(t, publicURL)

	t.Run("oauth_authorization_server_metadata", func(t *testing.T) {
		resp, err := http.Get(publicURL + "/.well-known/oauth-authorization-server")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		var meta map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
			t.Fatal(err)
		}
		if meta["issuer"] != publicURL {
			t.Fatalf("issuer %v", meta["issuer"])
		}
	})

	t.Run("oauth_token_returns_proxy_and_mcp_sees_real_token", func(t *testing.T) {
		form := url.Values{
			"grant_type":   []string{"authorization_code"},
			"code":         []string{"test-code"},
			"redirect_uri": []string{"http://localhost:5555/cb"},
			"resource":     []string{"undefined"},
		}.Encode()
		req, err := http.NewRequest(http.MethodPost, publicURL+"/oauth/token", strings.NewReader(form))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("token status %d: %s", resp.StatusCode, body)
		}
		var tr map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
			t.Fatal(err)
		}
		proxy, _ := tr["access_token"].(string)
		if proxy == "" || proxy == realOpenShiftLikeToken {
			t.Fatalf("expected distinct proxy token in JSON, got %q", proxy)
		}

		mcpBody := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
		mreq, err := http.NewRequest(http.MethodPost, publicURL+"/mcp", bytes.NewReader([]byte(mcpBody)))
		if err != nil {
			t.Fatal(err)
		}
		mreq.Header.Set("Content-Type", "application/json")
		mreq.Header.Set("Authorization", "Bearer "+proxy)
		mresp, err := http.DefaultClient.Do(mreq)
		if err != nil {
			t.Fatal(err)
		}
		defer mresp.Body.Close()
		if mresp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(mresp.Body)
			t.Fatalf("mcp status %d: %s", mresp.StatusCode, b)
		}
		if gotAuth != "Bearer "+realOpenShiftLikeToken {
			t.Fatalf("backend Authorization = %q; want Bearer + real token", gotAuth)
		}
	})
}

// TestShieldOAuthCallbackRedirect exercises /oauth/callback state unpacking and redirect.
func TestShieldOAuthCallbackRedirect(t *testing.T) {
	bin := buildShieldBinary(t)
	listenAddr := freeListenAddr(t)
	publicURL := "http://" + listenAddr
	env := append(os.Environ(),
		"OPENSHIFT_OAUTH_TOKEN_URL=http://127.0.0.1:9",
		"OAUTH_AUTHORIZATION_SERVERS="+publicURL,
		"MCP_BACKEND_URL=http://127.0.0.1:9",
		"MCP_SHIELD_DIRECT_TOOL_ROUTING=false",
		"INSPECTOR_ORIGIN=*",
		"OAUTH_CLIENT_ID=e2e-cb",
	)
	time.Sleep(50 * time.Millisecond)
	startShieldProcess(t, bin, listenAddr, env)
	waitHealthy(t, publicURL)

	state := "clientstate%7Credirect_uri%3Dhttp%253A%252F%252Flocalhost%253A7777%252Fcb"
	u := publicURL + "/oauth/callback?code=abc123&state=" + state
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 302, got %d: %s", resp.StatusCode, b)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "code=abc123") || !strings.Contains(loc, "localhost:7777") {
		t.Fatalf("Location: %q", loc)
	}
}

func freeListenAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}
