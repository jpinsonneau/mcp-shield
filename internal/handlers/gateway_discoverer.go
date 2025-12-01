package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GatewayDiscoverer handles mcp-gateway detection and upstream server discovery
type GatewayDiscoverer struct {
	logger          *slog.Logger
	gatewayURL      string
	upstreamServers map[string]*UpstreamServer // Map of server name to server config
	httpClient      *http.Client
	mu              sync.RWMutex
	stopDiscovery   chan struct{}
	onServersUpdate func(servers map[string]*UpstreamServer) // Callback when servers are discovered/updated
}

// NewGatewayDiscoverer creates a new gateway discoverer
func NewGatewayDiscoverer(logger *slog.Logger, backendURL string, onServersUpdate func(servers map[string]*UpstreamServer)) *GatewayDiscoverer {
	discoverer := &GatewayDiscoverer{
		logger:          logger,
		gatewayURL:      "",
		upstreamServers: make(map[string]*UpstreamServer),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		stopDiscovery:   make(chan struct{}),
		onServersUpdate: onServersUpdate,
	}

	// Try to detect if backend is mcp-gateway
	if backendURL != "" {
		logger.Info("Attempting to detect mcp-gateway from backend URL", "backend_url", backendURL)
		if discoverer.detectGateway(backendURL) {
			discoverer.gatewayURL = backendURL
			logger.Info("Detected mcp-gateway, enabling automatic upstream server discovery", "gateway_url", backendURL)
			// Initial discovery
			go discoverer.discoverUpstreamServersFromGateway(context.Background())
			// Start periodic discovery from gateway
			go discoverer.discoverFromGatewayPeriodically(context.Background())
		} else {
			logger.Info("Backend does not appear to be mcp-gateway, using as fallback only", "backend_url", backendURL)
		}
	}

	return discoverer
}

// IsGateway returns true if a gateway was detected
func (gd *GatewayDiscoverer) IsGateway() bool {
	gd.mu.RLock()
	defer gd.mu.RUnlock()
	return gd.gatewayURL != ""
}

// GetGatewayURL returns the gateway URL if detected
func (gd *GatewayDiscoverer) GetGatewayURL() string {
	gd.mu.RLock()
	defer gd.mu.RUnlock()
	return gd.gatewayURL
}

// GetUpstreamServers returns a copy of the discovered upstream servers
func (gd *GatewayDiscoverer) GetUpstreamServers() map[string]*UpstreamServer {
	gd.mu.RLock()
	defer gd.mu.RUnlock()

	// Return a copy to avoid race conditions
	servers := make(map[string]*UpstreamServer)
	for name, server := range gd.upstreamServers {
		servers[name] = server
	}
	return servers
}

// detectGateway attempts to detect if the backend URL is an mcp-gateway instance
func (gd *GatewayDiscoverer) detectGateway(backendURL string) bool {
	statusURL := strings.TrimSuffix(backendURL, "/")
	if !strings.HasSuffix(statusURL, "/status") {
		statusURL = statusURL + "/status"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", statusURL, nil)
	if err != nil {
		gd.logger.Debug("Failed to create status request", "error", err)
		return false
	}

	resp, err := gd.httpClient.Do(req)
	if err != nil {
		gd.logger.Debug("Failed to reach status endpoint (not a gateway?)", "status_url", statusURL, "error", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		gd.logger.Debug("Status endpoint returned non-200 (not a gateway?)", "status", resp.StatusCode)
		return false
	}

	var statusResponse GatewayStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResponse); err != nil {
		gd.logger.Debug("Failed to parse status response as gateway format (not a gateway?)", "error", err)
		return false
	}

	if statusResponse.Servers == nil {
		gd.logger.Debug("Status response missing servers array (not a gateway?)")
		return false
	}

	gd.logger.Info("Detected mcp-gateway instance", "server_count", len(statusResponse.Servers))
	return true
}

// discoverUpstreamServersFromGateway discovers upstream servers from mcp-gateway's /status endpoint
func (gd *GatewayDiscoverer) discoverUpstreamServersFromGateway(ctx context.Context) error {
	gd.mu.RLock()
	gatewayURL := gd.gatewayURL
	gd.mu.RUnlock()

	if gatewayURL == "" {
		return fmt.Errorf("gateway URL not configured")
	}

	statusURL := strings.TrimSuffix(gatewayURL, "/")
	if !strings.HasSuffix(statusURL, "/status") {
		statusURL = statusURL + "/status"
	}

	gd.logger.Info("Discovering upstream servers from mcp-gateway", "status_url", statusURL)

	req, err := http.NewRequestWithContext(ctx, "GET", statusURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := gd.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch gateway status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("gateway returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var statusResponse GatewayStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResponse); err != nil {
		return fmt.Errorf("failed to parse gateway status: %w", err)
	}

	gd.logger.Info("Discovered servers from gateway", "server_count", len(statusResponse.Servers))

	// Update upstream servers from gateway response
	gd.mu.Lock()
	for _, serverStatus := range statusResponse.Servers {
		serverName := serverStatus.Name
		if serverName == "" {
			serverName = serverStatus.URL
		}

		if existing, exists := gd.upstreamServers[serverName]; exists {
			if existing.URL != serverStatus.URL || existing.ToolPrefix != serverStatus.ToolPrefix {
				gd.logger.Info("Updating upstream server from gateway",
					"name", serverName,
					"old_url", existing.URL,
					"new_url", serverStatus.URL,
					"old_prefix", existing.ToolPrefix,
					"new_prefix", serverStatus.ToolPrefix)
				existing.URL = serverStatus.URL
				existing.ToolPrefix = serverStatus.ToolPrefix
			}
		} else {
			gd.upstreamServers[serverName] = &UpstreamServer{
				Name:       serverName,
				URL:        serverStatus.URL,
				ToolPrefix: serverStatus.ToolPrefix,
				Enabled:    true,
				Tools:      []string{},
				sessions:   make(map[string]string),
			}
			gd.logger.Info("Added upstream server from gateway",
				"name", serverName,
				"url", serverStatus.URL,
				"prefix", serverStatus.ToolPrefix)
		}
	}
	serversCopy := make(map[string]*UpstreamServer)
	for name, server := range gd.upstreamServers {
		serversCopy[name] = server
	}
	gd.mu.Unlock()

	// Notify callback if provided
	if gd.onServersUpdate != nil {
		gd.onServersUpdate(serversCopy)
	}

	return nil
}

// discoverFromGatewayPeriodically periodically discovers upstream servers from gateway
func (gd *GatewayDiscoverer) discoverFromGatewayPeriodically(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-gd.stopDiscovery:
			return
		case <-ticker.C:
			if err := gd.discoverUpstreamServersFromGateway(ctx); err != nil {
				gd.logger.Warn("Failed to discover upstream servers from gateway", "error", err)
			}
		}
	}
}
