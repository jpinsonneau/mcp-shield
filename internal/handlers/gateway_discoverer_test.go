package handlers

import (
	"encoding/json"
	"testing"
)

func TestGatewayStatusResponse_Unmarshal(t *testing.T) {
	raw := `{
		"servers": [
			{
				"url": "http://prom.svc:8080/mcp",
				"name": "prometheus",
				"toolPrefix": "prom_"
			}
		],
		"overallValid": true,
		"totalServers": 1,
		"healthyServers": 1,
		"unHealthyServers": 0,
		"toolConflicts": 0,
		"timestamp": "2025-01-01T00:00:00Z"
	}`
	var gs GatewayStatusResponse
	if err := json.Unmarshal([]byte(raw), &gs); err != nil {
		t.Fatal(err)
	}
	if len(gs.Servers) != 1 {
		t.Fatalf("servers len %d", len(gs.Servers))
	}
	if gs.Servers[0].Name != "prometheus" || gs.Servers[0].ToolPrefix != "prom_" {
		t.Fatalf("%+v", gs.Servers[0])
	}
	if !gs.OverallValid || gs.TotalServers != 1 {
		t.Fatalf("flags %+v", gs)
	}
	if gs.Timestamp.IsZero() {
		t.Fatal("timestamp not parsed")
	}
}

func TestGatewayDiscoverer_skipsWhenDirectRoutingDisabled(t *testing.T) {
	called := false
	gd := NewGatewayDiscoverer(discardLogger(), "http://localhost:9999", func(map[string]*UpstreamServer) {
		called = true
	}, false)
	if gd.IsGateway() {
		t.Fatal("gateway should not be detected when discovery disabled")
	}
	if gd.GetGatewayURL() != "" {
		t.Fatal("expected empty gateway URL")
	}
	if called {
		t.Fatal("callback should not run")
	}
}
