package handlers

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testToolRouter(t *testing.T) *ToolRouter {
	t.Helper()
	return &ToolRouter{
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		upstreamServers: make(map[string]*UpstreamServer),
		httpClient:      &http.Client{Timeout: 2 * time.Second},
		stopDiscovery:   make(chan struct{}),
	}
}

func TestToolRouter_RouteToolCall_byPrefixUndiscovered(t *testing.T) {
	tr := testToolRouter(t)
	tr.UpdateUpstreamServers(map[string]*UpstreamServer{
		"prom": {
			Name:       "prom",
			URL:        "http://prom.example/mcp",
			ToolPrefix: "prom_",
			Enabled:    true,
			Tools:      nil,
			sessions:   make(map[string]string),
		},
	})
	url, tool, err := tr.RouteToolCall("prom_metrics")
	if err != nil {
		t.Fatal(err)
	}
	if url != "http://prom.example/mcp" || tool != "metrics" {
		t.Fatalf("url=%q tool=%q", url, tool)
	}
}

func TestToolRouter_RouteToolCall_byDiscoveredTools(t *testing.T) {
	tr := testToolRouter(t)
	tr.UpdateUpstreamServers(map[string]*UpstreamServer{
		"prom": {
			Name:       "prom",
			URL:        "http://prom.example/mcp",
			ToolPrefix: "prom_",
			Enabled:    true,
			Tools:      []string{"metrics", "labels"},
			sessions:   make(map[string]string),
		},
	})
	_, _, err := tr.RouteToolCall("prom_unknown")
	if err == nil {
		t.Fatal("expected error for unknown tool when list is populated")
	}
	url, tool, err := tr.RouteToolCall("prom_metrics")
	if err != nil {
		t.Fatal(err)
	}
	if tool != "metrics" || url != "http://prom.example/mcp" {
		t.Fatalf("url=%q tool=%q", url, tool)
	}
}

func TestToolRouter_RouteToolCall_noServers(t *testing.T) {
	tr := testToolRouter(t)
	_, _, err := tr.RouteToolCall("any")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestToolRouter_GetOrEstablishSession_jsonSession(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"sessionId": "upstream-sid-1",
			},
		})
	}))
	defer up.Close()

	tr := testToolRouter(t)
	tr.UpdateUpstreamServers(map[string]*UpstreamServer{
		"s": {
			Name:     "s",
			URL:      up.URL,
			Enabled:  true,
			sessions: make(map[string]string),
		},
	})

	sid, err := tr.GetOrEstablishSession(context.Background(), up.URL, "client-1", "tok")
	if err != nil {
		t.Fatal(err)
	}
	if sid != "upstream-sid-1" {
		t.Fatalf("session id = %q", sid)
	}
	sid2, err := tr.GetOrEstablishSession(context.Background(), up.URL, "client-1", "tok")
	if err != nil || sid2 != "upstream-sid-1" {
		t.Fatalf("second call = %q, %v", sid2, err)
	}
}
