# MCP Shield Comparisons

This document compares MCP Shield with alternative solutions to help you choose the right tool for your use case.

## Why Not Use the Official OpenShift oauth-proxy?

You might wonder why we don't use the [official OpenShift oauth-proxy](https://github.com/openshift/oauth-proxy) project. Here's why:

The official `oauth-proxy` is a **reverse proxy** designed to:
- Authenticate users via OpenShift OAuth
- Proxy authenticated requests to upstream services
- Manage session cookies and authentication state

However, **MCP clients** (like the MCP Inspector) have different requirements:

### Authentication Method: Bearer Tokens vs Cookies

- **Official oauth-proxy**: Uses **cookie-based sessions** - it sets cookies after authentication and validates them on subsequent requests. The server maintains session state.
- **MCP clients**: Use **Bearer tokens** in the `Authorization` header - they perform the OAuth flow themselves, cache the access token locally (client-side), and send it with each request. The server is stateless.

**How agentic CLI clients handle authentication with MCP Shield:**
1. The agentic CLI client completes the OAuth flow and receives a **proxy token** (not the real user token)
2. **The agentic CLI client caches the proxy token locally** (in its local storage/cache)
3. The agentic CLI client sends the proxy token in the `Authorization: Bearer <proxy_token>` header with each MCP request
4. **MCP Shield exchanges the proxy token for the real user token** before forwarding to the MCP server
5. The MCP server receives the real token and uses it to authenticate with Prometheus
6. **No server-side sessions** - the MCP server is stateless and processes each request independently
7. **Security benefit**: Agentic CLI clients never have access to the real user token - only the proxy token, which is only valid for this MCP Shield instance

MCP clients need to:
1. Discover OAuth endpoints via `/.well-known/oauth-authorization-server`
2. Register as an OAuth client via `/oauth/register`
3. Initiate OAuth flow via `/oauth2/start`
4. Exchange authorization codes for tokens via `/oauth/token` (receives proxy token)
5. Cache the proxy token locally and send it with each subsequent MCP request
6. MCP Shield handles the exchange of proxy token → real token transparently

### Missing OAuth Discovery Endpoints

The official oauth-proxy doesn't provide the OAuth 2.0 discovery endpoints that MCP clients require:

1. **OAuth Discovery** (`/.well-known/oauth-authorization-server`) - MCP clients need this to discover OAuth endpoints
2. **Client Registration** (`/oauth/register`) - MCP Inspector performs dynamic client registration
3. **OAuth Start Flow** (`/oauth2/start`) - Needs to redirect to OpenShift OAuth with proper parameters and handle dynamic localhost redirect URIs
4. **OAuth Callback** (`/oauth/callback`) - Needs to handle OpenShift callbacks and restore original client redirect URIs
5. **Token Exchange** (`/oauth/token`) - Requires:
   - Filtering of `resource=undefined` parameter that OpenShift rejects
   - Fixing redirect URIs to match authorization step
   - Adding Basic Auth headers required by OpenShift
   - **Generating proxy tokens** instead of returning real user tokens

### MCP Shield Solution

MCP Shield is specifically designed to:
- ✅ Provide OAuth 2.0 discovery endpoints that MCP clients expect
- ✅ Handle OpenShift-specific OAuth flows (PKCE, token exchange)
- ✅ Support Bearer token authentication (not cookie-based)
- ✅ **Proxy token system**: Generate proxy tokens for clients instead of exposing real user tokens
  - Clients receive proxy tokens that are only valid for this MCP Shield instance
  - Real user tokens are never exposed to clients
  - Proxy tokens are time-limited (configurable TTL, default: 24 hours)
  - Enhanced security: even if a proxy token is compromised, it cannot be used to directly access OpenShift resources
- ✅ **Token exchange**: Exchange proxy tokens for real tokens when forwarding MCP requests
  - Transparent exchange happens server-side before forwarding to MCP server
  - Real tokens are only used server-side and never exposed to clients
- ✅ Handle dynamic localhost redirect URIs via callback proxy mechanism
  - Intercepts dynamic `localhost:XXXX/callback` redirect URIs
  - Uses fixed callback URL for OpenShift OAuth
  - Restores original redirect URI after authentication
- ✅ Filter problematic parameters (`resource=undefined`) that OpenShift rejects
- ✅ Fix redirect URIs in token exchange to match authorization step
- ✅ Add required Basic Auth headers for OpenShift OAuth token endpoint
- ✅ Proxy MCP protocol requests to the backend MCP server
  - Handles `/mcp`, `/mcp/`, and root path (`/`) requests
  - Exchanges proxy tokens for real tokens before forwarding
- ✅ CORS support for browser-based OAuth flows (MCP Inspector)
- ✅ Work seamlessly with MCP Inspector, agentic CLI clients, and other MCP clients
- ✅ Run as a lightweight sidecar without proxying all traffic
- ✅ Stateless operation - no server-side session management

**In summary**: The official oauth-proxy is designed for browser-based cookie authentication, while MCP clients need programmatic OAuth with Bearer tokens. This project fills that gap by providing:
1. The OAuth discovery and token exchange endpoints that MCP requires
2. A proxy token system that enhances security by preventing clients from accessing real user tokens
3. OpenShift-specific OAuth flow handling (PKCE, parameter filtering, redirect URI management)
4. Support for dynamic localhost redirect URIs used by MCP clients like agentic CLI clients

## Why Not Use mcp-gateway? (Use Both Together!)

You might also wonder why we don't use [mcp-gateway](https://github.com/kagenti/mcp-gateway), which is an Envoy-based MCP Gateway that also provides OAuth support. Here's why they serve different purposes, and when you might want to use both together:

### Architecture Differences

- **mcp-gateway**: A full gateway infrastructure component built on Envoy and Gateway API
  - Requires Istio, Gateway API CRDs, and a controller
  - Acts as a centralized gateway for multiple MCP servers
  - More complex deployment with multiple components (broker, router, controller)
  - Designed for multi-tenant, multi-server scenarios

- **MCP Shield**: A lightweight sidecar designed for single MCP server deployments
  - Runs alongside your MCP server in the same pod
  - No external dependencies (no Istio, Gateway API, or controller required)
  - Simple deployment - just add as a sidecar container
  - Designed for direct integration with a single MCP server

### OAuth Implementation Differences

**mcp-gateway's OAuth support:**
- Provides OAuth Protected Resource discovery (`/.well-known/oauth-protected-resource`)
- Focuses on token validation and authorization
- Assumes OAuth flow is handled elsewhere
- Does not implement the complete OAuth 2.0 flow endpoints that MCP clients need

**MCP Shield's OAuth support:**
- ✅ Implements **complete OAuth 2.0 flow** for MCP clients:
  - OAuth discovery (`/.well-known/oauth-authorization-server`)
  - Client registration (`/oauth/register`)
  - OAuth start flow (`/oauth2/start`) with dynamic redirect URI handling
  - OAuth callback (`/oauth/callback`) with redirect URI restoration
  - Token exchange (`/oauth/token`) with OpenShift-specific handling
- ✅ **Proxy token system** for enhanced security
- ✅ **OpenShift-specific handling**: PKCE, parameter filtering, redirect URI fixing
- ✅ **Dynamic localhost redirect URI support** for agentic CLI clients and similar MCP clients

### Use Case Differences

**Use mcp-gateway when:**
- You need to aggregate multiple MCP servers
- You want a centralized gateway infrastructure
- You're already using Istio and Gateway API
- You have a separate OAuth infrastructure and just need token validation
- You need advanced routing and load balancing across multiple MCP servers

**Use MCP Shield when:**
- You have a single MCP server (like prometheus-mcp-server, loki-mcp-server, or kubernetes-mcp-server)
- You want a simple sidecar deployment without external dependencies
- You need complete OAuth flow handling for MCP clients
- You're deploying to OpenShift and need OpenShift-specific OAuth handling
- You want proxy tokens for enhanced security
- You need support for dynamic localhost redirect URIs (agentic CLI clients)
- You're using mcp-gateway and want direct tool routing for better performance

**Use MCP Shield WITH mcp-gateway when:**
- You need mcp-gateway's multi-server aggregation capabilities
- You also need complete OAuth 2.0 flow handling (discovery, registration, token exchange)
- You want mcp-gateway to use dynamic Authorization headers from OAuth tokens (not static credentials)
- You're deploying to OpenShift and need OpenShift-specific OAuth handling
- You want proxy tokens for enhanced security
- You need support for dynamic localhost redirect URIs (agentic CLI clients)
- You want **direct tool routing** for better performance (tool calls bypass mcp-gateway)

When using MCP Shield with mcp-gateway:
- MCP Shield runs as a sidecar alongside mcp-gateway, handling OAuth flows
- **Automatic Gateway Discovery**: MCP Shield automatically detects mcp-gateway and discovers upstream servers from its `/status` endpoint
- **Direct Tool Routing**: MCP Shield routes tool calls directly to upstream MCP servers, bypassing mcp-gateway for better performance
  - Tool calls go: Client → MCP Shield → Upstream MCP Server (direct)
  - Non-tool requests (like `tools/list`) go: Client → MCP Shield → mcp-gateway (for aggregation)
- **Session Management**: MCP Shield automatically establishes and manages sessions with upstream servers for direct routing
- MCP Shield forwards requests to mcp-gateway with the Authorization header containing the real OAuth token
- mcp-gateway uses the Authorization header from MCP Shield when connecting to backend MCP servers
- This provides the best of both worlds: multi-server aggregation (mcp-gateway) + complete OAuth flow handling (MCP Shield) + direct tool routing for performance
- **Important**: Do not configure static credentials for backend servers in mcp-gateway when using MCP Shield, as the dynamic Authorization header from MCP Shield should be used instead

See the [MCP Gateway deployment guide](examples/mcp-gateway.md), [Direct Tool Routing documentation](direct-tool-routing.md), and [MCP Gateway integration](mcp-gateway-integration.md) (including `MCP_SHIELD_DIRECT_TOOL_ROUTING=false` and [mcp-gateway#414](https://github.com/Kuadrant/mcp-gateway/issues/414)) for details on deploying MCP Shield with mcp-gateway.

### Summary

mcp-gateway is a powerful solution for multi-server MCP deployments, while MCP Shield provides complete OAuth flow handling for MCP clients, especially for OpenShift environments. They can be used independently or together:

- **MCP Shield alone**: Best for single MCP server deployments that need complete OAuth flow handling
- **mcp-gateway alone**: Best for multi-server deployments with existing OAuth infrastructure
- **MCP Shield + mcp-gateway**: Best for multi-server deployments that need complete OAuth flow handling with OpenShift-specific features, proxy token security, and direct tool routing for better performance

**Key Features When Using MCP Shield with mcp-gateway:**
- ✅ **Automatic Gateway Discovery**: MCP Shield automatically detects mcp-gateway and discovers upstream servers
- ✅ **Direct Tool Routing**: Tool calls bypass mcp-gateway and go directly to upstream servers, reducing latency
- ✅ **Complete OAuth Flow**: Full OAuth 2.0 discovery, registration, and token exchange support
- ✅ **Proxy Token Security**: Enhanced security with proxy tokens instead of exposing real user tokens
- ✅ **Session Management**: Automatic session establishment and management for direct routing

If you're running a single MCP server (like prometheus-mcp-server) and need full OAuth support for MCP clients, MCP Shield provides a simpler, more focused solution. If you need to aggregate multiple MCP servers and also need complete OAuth flow handling, use MCP Shield as a sidecar with mcp-gateway to get the benefits of both: multi-server aggregation, complete OAuth flow handling, and direct tool routing for optimal performance.

