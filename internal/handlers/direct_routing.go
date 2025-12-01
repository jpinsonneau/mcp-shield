package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jpinsonn/mcp-shield/internal/tokenstore"
)

// DirectRoutingResult contains the result of attempting direct routing
type DirectRoutingResult struct {
	Success           bool
	UpstreamURL       string
	UpstreamToolName  string
	UpstreamSessionID string
	ModifiedBody      []byte
}

// tryDirectRouting attempts to route a tool call directly to an upstream server
func tryDirectRouting(
	logger *slog.Logger,
	toolRouter *ToolRouter,
	toolName string,
	jsonRPC map[string]interface{},
	requestBody []byte,
	authHeader string,
	tokenStore *tokenstore.TokenStore,
	ctx context.Context,
) (*DirectRoutingResult, error) {
	if toolRouter == nil {
		return &DirectRoutingResult{Success: false}, nil
	}

	// Try to route directly to upstream server
	upstream, upstreamTool, err := toolRouter.RouteToolCall(toolName)
	if err != nil {
		logger.Debug("Could not route tool directly", "tool_name", toolName, "error", err)
		return &DirectRoutingResult{Success: false}, nil
	}

	logger.Info("Routing tool call directly to upstream server",
		"tool_name", toolName,
		"upstream_tool", upstreamTool,
		"upstream_url", upstream)

	// Update tool name in request to use upstream tool name (without prefix)
	params, ok := jsonRPC["params"].(map[string]interface{})
	if !ok {
		return &DirectRoutingResult{Success: false}, fmt.Errorf("invalid params in JSON-RPC request")
	}

	if upstreamTool != toolName {
		params["name"] = upstreamTool
	}

	// Extract client session ID from request
	clientSessionID := ""
	if sid, ok := jsonRPC["sessionId"].(string); ok && sid != "" {
		clientSessionID = sid
	} else if sid, ok := params["sessionId"].(string); ok && sid != "" {
		clientSessionID = sid
	}

	// If no client session ID, generate one for internal tracking
	if clientSessionID == "" {
		randomBytes := make([]byte, 16)
		if _, err := rand.Read(randomBytes); err == nil {
			clientSessionID = hex.EncodeToString(randomBytes)
		} else {
			clientSessionID = fmt.Sprintf("%x", time.Now().UnixNano())
		}
		logger.Debug("Generated internal clientSessionID for direct routing", "clientSessionID", clientSessionID)
	}

	// Extract auth token for session establishment
	authToken := ""
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			// Try to exchange proxy token for real token
			if realToken, found := tokenStore.Get(parts[1]); found {
				authToken = realToken
			} else {
				authToken = parts[1] // Use as-is if not a proxy token
			}
		}
	}

	// Establish or get upstream session ID
	upstreamSessionID, err := toolRouter.GetOrEstablishSession(ctx, upstream, clientSessionID, authToken)
	if err != nil {
		logger.Warn("Failed to establish upstream session", "error", err, "upstream_url", upstream)
		return &DirectRoutingResult{Success: false}, err
	}

	// Use upstream session ID
	jsonRPC["sessionId"] = upstreamSessionID
	params["sessionId"] = upstreamSessionID
	logger.Info("Using upstream session ID for tool call",
		"client_session", clientSessionID,
		"upstream_session", upstreamSessionID)

	// Re-marshal with updated tool name and session ID
	modifiedBody, err := json.Marshal(jsonRPC)
	if err != nil {
		logger.Warn("Failed to update request for upstream routing", "error", err)
		return &DirectRoutingResult{Success: false}, err
	}

	logger.Debug("Updated request for upstream routing",
		"original_tool", toolName,
		"upstream_tool", upstreamTool,
		"upstream_session", upstreamSessionID)

	return &DirectRoutingResult{
		Success:           true,
		UpstreamURL:       upstream,
		UpstreamToolName:  upstreamTool,
		UpstreamSessionID: upstreamSessionID,
		ModifiedBody:      modifiedBody,
	}, nil
}
