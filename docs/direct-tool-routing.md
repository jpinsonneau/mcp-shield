# Direct Tool Routing in MCP Shield

This document describes the direct tool routing feature that allows MCP Shield to route tool calls directly to upstream MCP servers, bypassing mcp-gateway for tool execution while keeping mcp-gateway available for authentication/authorization.

## Overview

Previously, all MCP requests (including tool calls) went through mcp-gateway:
```
Client → mcp-shield → mcp-gateway → upstream MCP servers
```

With direct tool routing, tool calls go directly to upstream servers:
```
Client → mcp-shield → upstream MCP servers (for tool calls)
Client → mcp-shield → mcp-gateway (for auth/authz, optional)
```

## Architecture

### Components

1. **ToolRouter**: 
   - Discovers upstream servers from mcp-gateway's `/status` endpoint
   - Discovers tools from upstream servers
   - Routes tool calls to appropriate upstream servers
   - Manages session establishment and caching
2. **MCPProxyHandler**: Updated to use ToolRouter for direct routing and session management
3. **Upstream Server Discovery**: Automatic discovery from mcp-gateway (no manual configuration needed)

### Flow

1. **Upstream Server Discovery**: On startup, ToolRouter automatically discovers upstream servers from mcp-gateway's `/status` endpoint
2. **Tool Discovery**: ToolRouter periodically discovers tools from configured upstream servers
3. **Tool Call Detection**: MCPProxyHandler detects `tools/call` requests
4. **Direct Routing**: ToolRouter determines which upstream server handles the tool
5. **Session Establishment**: For direct routing, MCP Shield establishes a session with the upstream server:
   - Checks if session already exists for this client session
   - If not, calls `initialize` on the upstream server with the real OAuth token
   - Extracts the upstream session ID from the response
   - Sends `notifications/initialized` notification (MCP protocol requirement)
   - Caches the session mapping (client session ID → upstream session ID) for future use
6. **Request Forwarding**: Request is forwarded directly to the upstream server with:
   - Tool name prefix stripped (if configured)
   - Upstream session ID in both:
     - JSON body (`sessionId` field in the request)
     - HTTP header (`mcp-session-id` header)
   - Real OAuth token (exchanged from proxy token)
   - Original request body (with tool name and session ID updated)

## Configuration

### Automatic Discovery from mcp-gateway

MCP Shield automatically detects if `MCP_BACKEND_URL` points to an mcp-gateway instance by calling its `/status` endpoint. If detected, it automatically discovers upstream servers:

```bash
MCP_BACKEND_URL="http://mcp-gateway:8080"
```

**How it works**:
1. On startup, MCP Shield calls `http://mcp-gateway:8080/status` to detect if it's a gateway
2. If valid gateway status is returned, MCP Shield queries it to discover registered upstream servers
3. Extracts server URLs, names, and tool prefixes from the gateway's status response
4. Automatically configures routing based on discovered servers
5. Periodically refreshes the discovery (every 1 minute)

**Detection**: MCP Shield automatically detects mcp-gateway by:
- Calling the `/status` endpoint on `MCP_BACKEND_URL`
- Checking for a valid gateway status response format
- **If detected**: Enables automatic upstream server discovery and direct tool routing
- **If not detected**: Uses the backend as a regular fallback for all MCP requests (no direct routing attempted)

## How It Works

### Upstream Server Discovery

1. **Automatic Discovery**: ToolRouter queries mcp-gateway's `/status` endpoint every 1 minute
2. **Server Extraction**: Extracts server URLs, names, and tool prefixes from gateway status
3. **Configuration Update**: Updates upstream server configuration automatically

### Tool Discovery

1. **Periodic Discovery**: ToolRouter discovers tools from upstream servers every 5 minutes
2. **tools/list Request**: Sends `tools/list` JSON-RPC request to each upstream server
3. **Tool Caching**: Caches discovered tools per server
4. **Prefix Matching**: Uses tool prefixes to map gateway tool names to upstream servers

### Tool Call Routing

1. **Request Parsing**: MCPProxyHandler parses incoming JSON-RPC requests
2. **Tool Call Detection**: Detects `tools/call` method
3. **Tool Name Extraction**: Extracts tool name from request params
4. **Routing Decision**: ToolRouter determines upstream server:
   - Checks tool name prefix against configured servers
   - Strips prefix to get upstream tool name
   - Returns upstream server URL and tool name
5. **Session Establishment**: For direct routing, establishes session with upstream server:
   - Checks if session already exists for this client session
   - If not, calls `initialize` on upstream server with OAuth token
   - Extracts upstream session ID from response
   - Sends `notifications/initialized` notification
   - Caches session mapping for future use
6. **Request Modification**: Updates tool name and session ID in request:
   - Removes tool name prefix
   - Replaces client session ID with upstream session ID
7. **Direct Forwarding**: Forwards request directly to upstream server with:
   - Upstream tool name (prefix removed)
   - Upstream session ID in both:
     - JSON body (`sessionId` field)
     - HTTP header (`mcp-session-id` header)
   - Real OAuth token (exchanged from proxy token)

### Fallback Behavior

- **No Gateway Detected**: When `MCP_BACKEND_URL` is not a gateway, all requests (including tool calls) fall back to the backend. No direct routing is attempted.
- **No Upstream Servers**: If gateway is detected but no upstream servers are discovered yet, falls back to `MCP_BACKEND_URL` (the gateway itself)
- **Tool Not Found**: If a tool cannot be routed to any upstream server, falls back to `MCP_BACKEND_URL` (gateway or regular backend)
- **Discovery Failure**: Continues using cached tools, retries on next cycle
- **Routing Failure**: If direct routing fails for any reason (e.g., session establishment fails), automatically falls back to the backend

## Example Deployment

### With Automatic Gateway Discovery

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-shield
spec:
  template:
    spec:
      containers:
      - name: mcp-shield
        env:
        # OAuth Configuration
        - name: OAUTH_AUTHORIZATION_SERVERS
          value: "https://mcp-shield.apps.example.com"
        
        # Backend URL - MCP Shield will auto-detect if it's mcp-gateway
        - name: MCP_BACKEND_URL
          value: "http://mcp-gateway:8080"  # Will auto-detect gateway and discover upstream servers
```

### Without Gateway (Direct MCP Server)

When `MCP_BACKEND_URL` points to a regular MCP server (not mcp-gateway), MCP Shield automatically uses it as a fallback for all requests:

```yaml
        env:
        # OAuth Configuration
        - name: OAUTH_AUTHORIZATION_SERVERS
          value: "https://mcp-shield.apps.example.com"
        
        # Backend Configuration (regular MCP server, not gateway)
        - name: MCP_BACKEND_URL
          value: "http://prometheus-mcp-server:8080"  # Will be used as fallback
        - name: MCP_BACKEND_PATH
          value: "/mcp"  # Path for the MCP server endpoint
```

**Behavior**:
- MCP Shield detects that the backend is not a gateway
- All MCP requests (including tool calls) are forwarded to the backend
- No direct routing is attempted
- Works seamlessly with any MCP server

## Benefits

1. **Reduced Latency**: Tool calls bypass mcp-gateway, reducing hop count
2. **Simplified Architecture**: Fewer components in the request path
3. **Better Performance**: Direct connection to upstream servers
4. **Automatic Session Management**: MCP Shield handles session establishment and caching automatically
5. **Flexibility**: Can still use mcp-gateway for auth/authz if needed
6. **Backward Compatible**: Falls back to backend (gateway or regular MCP server) if no gateway detected or if routing fails
7. **Automatic Fallback**: When backend is not a gateway, automatically uses it for all requests without attempting direct routing

## Session Management

When routing tool calls directly to upstream servers, MCP Shield automatically manages sessions:

1. **Session Establishment**: On first tool call to an upstream server, MCP Shield:
   - Calls `initialize` on the upstream server with the real OAuth token
   - Extracts the upstream session ID from the response
   - Sends `notifications/initialized` notification (MCP protocol requirement)
   - Caches the session mapping (client session ID → upstream session ID)
   
2. **Session ID Usage**: When forwarding tool calls, MCP Shield includes the upstream session ID in:
   - The JSON-RPC request body (`sessionId` field)
   - The HTTP header (`mcp-session-id` header)
   
   This ensures compatibility with MCP servers that require the session ID in either location.

3. **Session Reuse**: Subsequent tool calls to the same upstream server:
   - Use the cached upstream session ID
   - No need to re-establish the session

4. **Session Isolation**: Each client session gets its own upstream session:
   - Sessions are isolated per client
   - Multiple clients can use the same upstream server simultaneously

## Limitations

1. **Tool Discovery**: Requires periodic discovery (5-minute interval)
2. **Prefix Required**: Tool prefixes must be configured correctly
3. **Session Establishment**: First tool call to each upstream server requires an `initialize` call (adds small latency)
4. **No Aggregation**: Each upstream server must be configured separately

## Migration Guide

### From mcp-gateway to Direct Routing

With automatic discovery, migration is automatic! Simply ensure `MCP_BACKEND_URL` points to your mcp-gateway:

**Before** (via mcp-gateway):
```bash
MCP_BACKEND_URL="http://mcp-gateway:8080"
MCP_BACKEND_PATH="/mcp"
```

**After** (automatic direct routing):
```bash
MCP_BACKEND_URL="http://mcp-gateway:8080"  # MCP Shield will auto-detect and discover upstream servers
```

MCP Shield will automatically:
1. Detect that `MCP_BACKEND_URL` points to mcp-gateway
2. Discover all upstream servers from the gateway's `/status` endpoint
3. Route tool calls directly to upstream servers
4. Use the gateway as fallback for non-tool requests

## Troubleshooting

### Tools Not Routing Directly

1. **Check Gateway Discovery**: Look for "Discovering upstream servers from mcp-gateway" in logs
2. **Check Gateway Status**: Verify mcp-gateway's `/status` endpoint is accessible
3. **Check Discovery**: Look for "Discovered servers from gateway" and "Discovered tools from server" in logs
4. **Check Prefixes**: Ensure tool prefixes match between gateway and discovered config
5. **Check Logs**: Look for "Routing tool call directly to upstream server"

### Gateway Discovery Failures

1. **Check Backend URL**: Verify `MCP_BACKEND_URL` is set correctly
2. **Check Connectivity**: Ensure mcp-gateway is reachable from mcp-shield
3. **Check Status Endpoint**: Verify `http://mcp-gateway:8080/status` returns valid JSON
4. **Check Logs**: 
   - Look for "Backend does not appear to be mcp-gateway, using as fallback only" if backend is not a gateway (this is normal)
   - Look for "Failed to discover upstream servers from gateway" warnings if gateway detection succeeded but discovery failed
5. **Retry**: Discovery retries every 1 minute automatically
6. **Not a Gateway**: If your backend is not mcp-gateway, this is expected behavior - MCP Shield will use it as a regular fallback

### Tool Not Found

1. **Verify Tool Exists**: Check upstream server's `tools/list` response
2. **Check Prefix**: Ensure tool name includes the correct prefix (if using gateway)
3. **Check Discovery**: Ensure tools were discovered successfully (if using gateway)
4. **Fallback**: Check if fallback to backend is working (look for "Could not route tool directly, using fallback backend" in logs)
5. **No Gateway**: If backend is not a gateway, tool calls will automatically fall back to the backend

### Session Establishment Failures

1. **Check Authorization**: Verify OAuth token is valid and has permissions
2. **Check Connectivity**: Ensure upstream server is reachable
3. **Check Initialize Response**: Look for "Failed to initialize upstream session" in logs
4. **Check Session ID**: Verify upstream server returns a session ID in initialize response
5. **Check Headers**: Look for "Set mcp-session-id header for upstream request" in logs (at DEBUG level)
6. **Check Both Locations**: Ensure session ID is in both JSON body and HTTP header
7. **Retry**: Session establishment happens on each first tool call to an upstream server

### Invalid Session ID Errors

If you're getting "Invalid session ID" errors on tool calls:

1. **Verify Session Establishment**: Check logs for "Established upstream session" message
2. **Check Session ID Format**: Verify the upstream server returns a valid session ID format
3. **Check Header**: Ensure `mcp-session-id` header is being set (check DEBUG logs)
4. **Check JSON Body**: Verify `sessionId` field is present in the JSON-RPC request body
5. **Check Token**: Ensure the OAuth token used for session establishment is still valid
6. **Check Session Cache**: If using cached sessions, verify the session hasn't expired on the upstream server

### Discovery Failures

1. **Check Connectivity**: Verify upstream servers are reachable (discovered from gateway)
2. **Check Gateway Status**: Verify mcp-gateway's `/status` endpoint returns valid server configurations
3. **Check Logs**: Look for "Failed to discover tools from server" warnings
4. **Retry**: Discovery retries every 5 minutes automatically

## Related Documentation

- [MCP Shield Architecture](../README.md)

