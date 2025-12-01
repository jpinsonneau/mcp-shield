package handlers

import (
	"bytes"
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

// UpstreamServer represents an upstream MCP server configuration
type UpstreamServer struct {
	Name       string            // Server name/identifier
	URL        string            // Full URL to the MCP server (e.g., "http://prometheus-mcp-server:8080/mcp")
	ToolPrefix string            // Prefix for tools from this server (e.g., "prometheus_")
	Enabled    bool              // Whether this server is enabled
	Tools      []string          // Cached list of tool names (discovered)
	sessions   map[string]string // Map of client session ID -> upstream session ID
	mu         sync.RWMutex
}

// GatewayStatusResponse represents the response from mcp-gateway's /status endpoint
type GatewayStatusResponse struct {
	Servers          []GatewayServerStatus `json:"servers"`
	OverallValid     bool                  `json:"overallValid"`
	TotalServers     int                   `json:"totalServers"`
	HealthyServers   int                   `json:"healthyServers"`
	UnHealthyServers int                   `json:"unHealthyServers"`
	ToolConflicts    int                   `json:"toolConflicts"`
	Timestamp        time.Time             `json:"timestamp"`
}

// GatewayServerStatus represents a single server in the gateway status response
type GatewayServerStatus struct {
	URL                    string                 `json:"url"`
	Name                   string                 `json:"name"`
	ToolPrefix             string                 `json:"toolPrefix"`
	ConnectionStatus       map[string]interface{} `json:"connectionStatus"`
	ProtocolValidation     map[string]interface{} `json:"protocolValidation"`
	CapabilitiesValidation map[string]interface{} `json:"capabilitiesValidation"`
	ToolConflicts          []interface{}          `json:"toolConflicts"`
	LastValidated          time.Time              `json:"lastValidated"`
}

// ToolRouter handles tool discovery and routing to upstream MCP servers
type ToolRouter struct {
	logger          *slog.Logger
	upstreamServers map[string]*UpstreamServer // Map of server name to server config
	httpClient      *http.Client
	mu              sync.RWMutex
	stopDiscovery   chan struct{} // Channel to stop periodic discovery
}

// NewToolRouter creates a new tool router
func NewToolRouter(logger *slog.Logger) *ToolRouter {
	router := &ToolRouter{
		logger:          logger,
		upstreamServers: make(map[string]*UpstreamServer),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		stopDiscovery: make(chan struct{}),
	}

	// Start background tool discovery
	go router.discoverToolsPeriodically(context.Background())

	return router
}

// UpdateUpstreamServers updates the upstream servers from gateway discovery
func (tr *ToolRouter) UpdateUpstreamServers(servers map[string]*UpstreamServer) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.upstreamServers = servers
	tr.logger.Info("Updated upstream servers from gateway", "server_count", len(servers))
}

// discoverToolsPeriodically discovers tools from upstream servers periodically
func (tr *ToolRouter) discoverToolsPeriodically(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute) // Discover every 5 minutes
	defer ticker.Stop()

	// Initial discovery
	tr.discoverAllTools(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tr.discoverAllTools(ctx)
		}
	}
}

// discoverAllTools discovers tools from all upstream servers
func (tr *ToolRouter) discoverAllTools(ctx context.Context) {
	tr.mu.RLock()
	servers := make([]*UpstreamServer, 0, len(tr.upstreamServers))
	for _, server := range tr.upstreamServers {
		if server.Enabled {
			servers = append(servers, server)
		}
	}
	tr.mu.RUnlock()

	if len(servers) == 0 {
		tr.logger.Debug("No upstream servers configured, skipping tool discovery")
		return
	}

	for _, server := range servers {
		go func(s *UpstreamServer) {
			if err := tr.discoverToolsFromServer(ctx, s); err != nil {
				tr.logger.Warn("Failed to discover tools from server", "server", s.Name, "error", err)
			}
		}(server)
	}
}

// discoverToolsFromServer discovers tools from a specific upstream server
func (tr *ToolRouter) discoverToolsFromServer(ctx context.Context, server *UpstreamServer) error {
	// Create tools/list request
	requestBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make request to upstream server
	req, err := http.NewRequestWithContext(ctx, "POST", server.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := tr.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request tools: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var jsonRPCResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jsonRPCResponse); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract tools
	result, ok := jsonRPCResponse["result"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid response format: missing result")
	}

	tools, ok := result["tools"].([]interface{})
	if !ok {
		return fmt.Errorf("invalid response format: missing tools array")
	}

	// Update server's tool list
	server.mu.Lock()
	server.Tools = make([]string, 0, len(tools))
	for _, tool := range tools {
		if toolMap, ok := tool.(map[string]interface{}); ok {
			if name, ok := toolMap["name"].(string); ok {
				server.Tools = append(server.Tools, name)
			}
		}
	}
	server.mu.Unlock()

	tr.logger.Info("Discovered tools from server", "server", server.Name, "tool_count", len(server.Tools))
	return nil
}

// RouteToolCall determines which upstream server should handle a tool call and returns its URL
func (tr *ToolRouter) RouteToolCall(toolName string) (string, string, error) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	if len(tr.upstreamServers) == 0 {
		return "", "", fmt.Errorf("no upstream servers configured")
	}

	// Try to find server by tool name prefix
	for _, server := range tr.upstreamServers {
		if !server.Enabled {
			continue
		}

		// Check if tool name starts with this server's prefix
		if server.ToolPrefix != "" && strings.HasPrefix(toolName, server.ToolPrefix) {
			// Strip prefix to get upstream tool name
			upstreamToolName := strings.TrimPrefix(toolName, server.ToolPrefix)
			server.mu.RLock()
			// Verify tool exists in server's tool list (if discovered)
			if len(server.Tools) > 0 {
				found := false
				for _, tool := range server.Tools {
					if tool == upstreamToolName {
						found = true
						break
					}
				}
				server.mu.RUnlock()
				if found {
					return server.URL, upstreamToolName, nil
				}
			} else {
				// Tools not yet discovered, but prefix matches - route anyway
				server.mu.RUnlock()
				tr.logger.Debug("Routing by prefix (tools not yet discovered)", "tool", toolName, "server", server.Name)
				return server.URL, upstreamToolName, nil
			}
		} else if server.ToolPrefix == "" {
			// No prefix - check if tool matches any discovered tool
			server.mu.RLock()
			for _, tool := range server.Tools {
				if toolName == tool {
					server.mu.RUnlock()
					return server.URL, tool, nil
				}
			}
			server.mu.RUnlock()
		}
	}

	return "", "", fmt.Errorf("tool not found: %s", toolName)
}

// GetOrEstablishSession gets or establishes a session with an upstream server for a given client session
func (tr *ToolRouter) GetOrEstablishSession(ctx context.Context, upstreamURL string, clientSessionID string, authToken string) (string, error) {
	tr.mu.RLock()
	var server *UpstreamServer
	for _, s := range tr.upstreamServers {
		if s.URL == upstreamURL {
			server = s
			break
		}
	}
	tr.mu.RUnlock()

	if server == nil {
		return "", fmt.Errorf("upstream server not found for URL: %s", upstreamURL)
	}

	server.mu.RLock()
	upstreamSessionID, exists := server.sessions[clientSessionID]
	server.mu.RUnlock()

	if exists {
		tr.logger.Debug("Using existing upstream session", "client_session", clientSessionID, "upstream_session", upstreamSessionID)
		return upstreamSessionID, nil
	}

	// Establish a new session with the upstream server
	tr.logger.Info("Establishing new session with upstream server", "upstream_url", upstreamURL, "client_session", clientSessionID)

	// Create initialize request
	initializeRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "mcp-shield",
				"version": "0.0.1",
			},
		},
	}

	bodyBytes, err := json.Marshal(initializeRequest)
	if err != nil {
		return "", fmt.Errorf("failed to marshal initialize request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", upstreamURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create initialize request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// Some MCP servers (like kubernetes-mcp-server) require Accept header with both JSON and SSE
	req.Header.Set("Accept", "application/json, text/event-stream")
	if authToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))
	}

	resp, err := tr.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to initialize upstream session: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		tr.logger.Warn("Upstream server returned non-200 during initialize",
			"status", resp.StatusCode,
			"response_body", string(bodyBytes),
			"upstream_url", upstreamURL)
		return "", fmt.Errorf("upstream server returned status %d during initialize: %s", resp.StatusCode, string(bodyBytes))
	}

	// Read response body first to handle both JSON and non-JSON responses
	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 10240)) // 10KB limit
	if readErr != nil {
		return "", fmt.Errorf("failed to read initialize response body: %w", readErr)
	}

	// Try to parse as JSON
	var jsonRPCResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &jsonRPCResponse); err != nil {
		// Not JSON - log the actual response for debugging
		tr.logger.Warn("Initialize response is not JSON",
			"upstream_url", upstreamURL,
			"response_body", string(bodyBytes),
			"content_type", resp.Header.Get("Content-Type"))
		// Check if session ID is in headers
		if sid := resp.Header.Get("mcp-session-id"); sid != "" {
			tr.logger.Info("Found session ID in response header", "session_id", sid)
			return sid, nil
		}
		return "", fmt.Errorf("failed to parse initialize response as JSON: %w (response: %s)", err, string(bodyBytes))
	}

	// Extract session ID from response (could be in result or in headers)
	// MCP servers typically return session ID in the response
	var sessionID string
	if result, ok := jsonRPCResponse["result"].(map[string]interface{}); ok {
		if sid, ok := result["sessionId"].(string); ok {
			sessionID = sid
		}
	}

	// Also check response headers
	if sessionID == "" {
		if sid := resp.Header.Get("mcp-session-id"); sid != "" {
			sessionID = sid
		}
	}

	// If still no session ID, use the client session ID as fallback
	if sessionID == "" {
		sessionID = clientSessionID
		tr.logger.Warn("No session ID in initialize response, using client session ID", "client_session", clientSessionID)
	}

	// Send notifications/initialized after initialize (MCP protocol requirement)
	initializedNotification := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		"params":  map[string]interface{}{},
	}
	if sessionID != "" {
		initializedNotification["sessionId"] = sessionID
	}

	notifBodyBytes, err := json.Marshal(initializedNotification)
	if err == nil {
		notifReq, err := http.NewRequestWithContext(ctx, "POST", upstreamURL, bytes.NewReader(notifBodyBytes))
		if err == nil {
			notifReq.Header.Set("Content-Type", "application/json")
			// Some MCP servers (like kubernetes-mcp-server) require Accept header with both JSON and SSE
			notifReq.Header.Set("Accept", "application/json, text/event-stream")
			if authToken != "" {
				notifReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))
			}
			if sessionID != "" {
				notifReq.Header.Set("mcp-session-id", sessionID)
			}
			// Send notification (don't wait for response or check errors - it's a notification)
			go func() {
				tr.httpClient.Do(notifReq)
			}()
			tr.logger.Debug("Sent notifications/initialized to upstream server", "upstream_url", upstreamURL, "session_id", sessionID)
		}
	}

	// Store the session mapping
	server.mu.Lock()
	server.sessions[clientSessionID] = sessionID
	server.mu.Unlock()

	tr.logger.Info("Established upstream session", "client_session", clientSessionID, "upstream_session", sessionID, "upstream_url", upstreamURL)
	return sessionID, nil
}

// GetUpstreamServerURL returns the URL for a specific upstream server by name
func (tr *ToolRouter) GetUpstreamServerURL(serverName string) (string, error) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	server, ok := tr.upstreamServers[serverName]
	if !ok || !server.Enabled {
		return "", fmt.Errorf("upstream server not found or disabled: %s", serverName)
	}

	return server.URL, nil
}
