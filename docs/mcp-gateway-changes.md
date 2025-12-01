# MCP Gateway Code Changes for Standalone Tool Forwarding

This document describes the code changes needed in `mcp-gateway` to enable standalone tool forwarding (without Envoy/router). These changes allow `mcp-shield` to work with `mcp-gateway` as a sidecar.

## Overview

The changes convert the broker's tool forwarding functions to methods, enable tool forwarding in standalone mode, and add session tracking to properly route tool calls to upstream MCP servers.

## Git Diff

See the [GitHub comparison](https://github.com/kagenti/mcp-gateway/compare/main...jpinsonneau:mcp-gateway:standalone-tool-forwarding) for the full diff.

```diff
diff --git a/internal/broker/broker.go b/internal/broker/broker.go
index 06c0d66..ab7ae4a 100644
--- a/internal/broker/broker.go
+++ b/internal/broker/broker.go
@@ -9,6 +9,7 @@ import (
 	"os"
 	"slices"
 	"strconv"
+	"sync"
 	"time"
 
 	"github.com/kagenti/mcp-gateway/internal/config"
@@ -28,6 +29,14 @@ type downstreamSessionID string
 // upstreamSessionID is for session IDs the gateway uses with upstream MCP servers
 type upstreamSessionID string
 
+// contextKey is a type for context keys
+type contextKey string
+
+const (
+	// sessionIDKey is the context key for storing the current session ID
+	sessionIDKey contextKey = "mcp-gateway-session-id"
+)
+
 // upstreamMCPURL identifies an upstream MCP server
 type upstreamMCPURL string
 
@@ -142,6 +151,10 @@ type mcpBrokerImpl struct {
 
 	logger *slog.Logger
 
+	// sessionMap tracks the current session ID for each active client session
+	// This is populated by the OnRegisterSession hook and used by tool handlers
+	sessionMap sync.Map // map[string]string - maps some identifier to session ID
+
 	// enforceToolFilter if set will ensure only a filtered list of tools is returned this list is based on the x-authorized-tools trusted header
 	enforceToolFilter bool
 
@@ -183,14 +196,20 @@ func NewBroker(logger *slog.Logger, opts ...func(*mcpBrokerImpl)) MCPBroker {
 	hooks := &server.Hooks{}
 
 	hooks.AddOnUnregisterSession(func(_ context.Context, session server.ClientSession) {
-		slog.Info("Client disconnected", "sessionID", session.SessionID())
+		sessionID := session.SessionID()
+		slog.Info("Client disconnected", "sessionID", sessionID)
+		// Clean up the session from the map
+		mcpBkr.sessionMap.Delete("current")
 	})
 
 	// Enhanced session registration to log gateway session assignment
 	hooks.AddOnRegisterSession(func(_ context.Context, session server.ClientSession) {
 		// Note that AddOnRegisterSession is for GET, not POST, for a session.
 		// https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#listening-for-messages-from-the-server
-		slog.Info("Gateway client connected with session", "gatewaySessionID", session.SessionID())
+		sessionID := session.SessionID()
+		slog.Info("Gateway client connected with session", "gatewaySessionID", sessionID)
+		// Store the session ID in the map for later retrieval
+		mcpBkr.sessionMap.Store("current", sessionID)
 	})
 
 	hooks.AddBeforeAny(func(_ context.Context, _ any, method mcp.MCPMethod, _ any) {
@@ -294,7 +313,7 @@ func (m *mcpBrokerImpl) RegisterServerWithConfig(
 	}
 	slog.Info("Discovered tools", "mcpURL", mcpServer.URL, "num tools", len(newTools))
 	slog.Info("Server registered", "url", mcpServer.URL, "totalServers", len(m.mcpServers))
-	m.listeningMCPServer.AddTools(toolsToServerTools(mcpServer.URL, newTools)...)
+	m.listeningMCPServer.AddTools(m.toolsToServerTools(mcpServer.URL, newTools)...)
 
 	return nil
 }
@@ -480,7 +499,7 @@ func (m *mcpBrokerImpl) discoverTools(ctx context.Context, upstream *upstreamMCP
 			// Add any tools added since the last notification
 			if len(newlyAddedTools) > 0 {
 				m.logger.Info("Adding tools", "mcpURL", upstream.URL, "#tools", len(newlyAddedTools))
-				m.listeningMCPServer.AddTools(toolsToServerTools(upstream.URL, newlyAddedTools)...)
+				m.listeningMCPServer.AddTools(m.toolsToServerTools(upstream.URL, newlyAddedTools)...)
 			}
 
 			// Delete any tools removed since the last notification
@@ -551,7 +570,7 @@ func (m *mcpBrokerImpl) retryDiscovery(ctx context.Context, upstream *upstreamMC
 			"attempt", attempt,
 			"tools", len(newTools))
 
-		m.listeningMCPServer.AddTools(toolsToServerTools(upstream.URL, newTools)...)
+		m.listeningMCPServer.AddTools(m.toolsToServerTools(upstream.URL, newTools)...)
 
 		return true, nil
 	})
@@ -811,29 +830,35 @@ func (upstream *upstreamMCP) prefixedName(tool string) toolName {
 	return toolName(fmt.Sprintf("%s%s", upstream.ToolPrefix, tool))
 }
 
-func toolToServerTool(newTool mcp.Tool) server.ServerTool {
+func (m *mcpBrokerImpl) toolToServerTool(newTool mcp.Tool) server.ServerTool {
 	return server.ServerTool{
 		Tool: newTool,
-		Handler: func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
-			return mcp.NewToolResultError("Kagenti MCP Broker doesn't forward tool calls"), nil
-		},
-		/* UNCOMMENT THIS TO TURN THE BROKER INTO A STAND-ALONE GATEWAY
 		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
+			// Get session ID from the session map
+			// For now, we use "current" as the key since we only track one active session
+			// In a multi-client scenario, we'd need a better key (e.g., from request headers)
+			sessionID := ""
+			if sessionIDValue, ok := m.sessionMap.Load("current"); ok {
+				if sid, ok := sessionIDValue.(string); ok {
+					sessionID = sid
+				}
+			}
+
+			// If no session ID found, use empty string (broker will handle session creation)
 			result, err := m.CallTool(ctx,
-				downstreamSessionID(request.GetString("Mcp-Session-Id", "")),
+				downstreamSessionID(sessionID),
 				request,
 			)
 			return result, err
-		}
-		*/
+		},
 	}
 }
 
-func toolsToServerTools(mcpURL string, newTools []mcp.Tool) []server.ServerTool {
+func (m *mcpBrokerImpl) toolsToServerTools(mcpURL string, newTools []mcp.Tool) []server.ServerTool {
 	tools := make([]server.ServerTool, 0)
 	for _, newTool := range newTools {
-		slog.Info("Federating tool", "mcpURL", mcpURL, "federated name", newTool.Name)
-		tools = append(tools, toolToServerTool(newTool))
+		m.logger.Info("Federating tool", "mcpURL", mcpURL, "federated name", newTool.Name)
+		tools = append(tools, m.toolToServerTool(newTool))
 	}
 
 	return tools
 }
```

## Key Changes Explained

### 1. Added `sync` Import
- Added `"sync"` to imports to support `sync.Map` for thread-safe session tracking.

### 2. Added Session Tracking Infrastructure
- Added `contextKey` type and `sessionIDKey` constant (currently unused but reserved for future use).
- Added `sessionMap sync.Map` field to `mcpBrokerImpl` struct to track active client sessions.

### 3. Enhanced Session Hooks
- Modified `OnRegisterSession` hook to store the session ID in `sessionMap` when a client connects.
- Modified `OnUnregisterSession` hook to clean up the session from `sessionMap` when a client disconnects.

### 4. Converted Functions to Methods
- Changed `toolToServerTool()` from a standalone function to a method `(m *mcpBrokerImpl) toolToServerTool()`.
- Changed `toolsToServerTools()` from a standalone function to a method `(m *mcpBrokerImpl) toolsToServerTools()`.
- Updated all call sites to use the method syntax (`m.toolsToServerTools(...)`).

### 5. Enabled Tool Forwarding
- Replaced the error-returning handler with actual tool forwarding logic.
- The handler now:
  1. Retrieves the session ID from `sessionMap`.
  2. Calls `m.CallTool()` to forward the request to the appropriate upstream MCP server.
  3. Returns the result to the client.

### 6. Improved Logging
- Changed from global `slog.Info()` to instance logger `m.logger.Info()` in `toolsToServerTools()` for consistency.

## Applying the Changes

To apply these changes to your `mcp-gateway` repository:

1. Navigate to the `mcp-gateway` repository:
   ```bash
   cd /path/to/mcp-gateway
   ```

2. Apply the patch:
   ```bash
   # Copy the diff above to a file
   git apply mcp-gateway-changes.patch
   ```

   Or manually apply the changes using the diff as a guide.

3. Build and test:
   ```bash
   make build
   make test
   ```

## Notes

- **Session Tracking**: The current implementation uses a "current" key in the session map, which works for single-client scenarios. For multi-client support, you may need to enhance this to use request headers or other identifiers to map sessions correctly.

- **Backward Compatibility**: These changes maintain backward compatibility with the Envoy/router deployment mode. The broker will work in both standalone mode (with these changes) and with Envoy/router (existing mode).

- **Testing**: After applying these changes, test the broker in standalone mode to ensure tool forwarding works correctly with `mcp-shield`.

## Related Documentation

- [MCP Gateway with MCP Shield Deployment Guide](../examples/mcp-gateway.md)
- [MCP Shield Examples](../examples/)

