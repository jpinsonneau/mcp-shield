# Deploying MCP Shield with MCP Gateway

MCP Shield can be deployed alongside the [MCP Gateway](https://github.com/kagenti/mcp-gateway) to provide OAuth 2.0 authentication for the gateway. While mcp-gateway provides aggregation and routing of multiple MCP servers, MCP Shield adds the complete OAuth 2.0 flow implementation needed for MCP clients like MCP Inspector and agentic CLI clients.

An example deployment is provided in `examples/openshift-mcp-gateway-sidecar.yml`.


## Prerequisites

**Important**: MCP Gateway requires code changes to enable standalone tool forwarding when used without Envoy/router. These changes are necessary for MCP Gateway to work with MCP Shield as a sidecar.

See [mcp-gateway-changes.md](../mcp-gateway-changes.md) for the complete git diff and detailed explanation of the required changes.

## Quick Start (Automated)

The easiest way to deploy is using the provided script:

```bash
cd examples
./deploy-openshift-mcp-gateway-sidecar.sh
```

This script will:
1. Detect your OpenShift cluster domain
2. Replace placeholders in the YAML
3. Create the OAuthClient
4. Deploy the application
5. Create a Route (optional)
6. Update environment variables

**Options:**
```bash
# Deploy to a specific namespace
./deploy-openshift-mcp-gateway-sidecar.sh --namespace mcp-system

# Use a custom OAuth client ID
./deploy-openshift-mcp-gateway-sidecar.sh --client-id my-mcp-gateway

# Deploy without creating a Route
./deploy-openshift-mcp-gateway-sidecar.sh --no-route

# Clean up deployment
./deploy-openshift-mcp-gateway-sidecar.sh --cleanup
```

## Manual Deployment

If you prefer to deploy manually, follow these steps:

### Step 1: Get Your OpenShift Cluster Domain

First, determine your OpenShift cluster domain:

```bash
# Get the cluster domain from the console route
oc get route console -n openshift-console -o jsonpath='{.spec.host}' | sed 's/console-openshift-console\.//' | sed 's/^apps\.//'

# Or from ingress config
oc get ingress.config cluster -o jsonpath='{.spec.domain}' | sed 's/^apps\.//'
```

### Step 2: Update the Example Deployment

Edit `examples/openshift-mcp-gateway-sidecar.yml` and replace `PLACEHOLDER` with your cluster domain:

```bash
# Replace PLACEHOLDER with your cluster domain
sed -i 's/PLACEHOLDER/your-cluster-domain.com/g' examples/openshift-mcp-gateway-sidecar.yml
```

Also configure environment variables in the MCP Shield container:
- `OAUTH_AUTHORIZATION_SERVERS` - Set to the public URL where MCP Shield is accessible
- `INSPECTOR_ORIGIN` - Set to the MCP Inspector origin URL (for CORS)
- `OAUTH_CLIENT_ID` - Set to match the OAuthClient name you'll create (default: `mcp-gateway`)
- `OAUTH_REDIRECT_URIS` - Optional: comma-separated list of additional redirect URIs
- `MCP_BACKEND_PATH` - Set to `/mcp` for MCP Gateway (this is the default)

**Note**: MCP Gateway runs on port 8080 for HTTP (broker) and port 50051 for gRPC (router). MCP Shield will proxy requests to the gateway's `/mcp` endpoint.

### Step 3: Create the OAuth Client

Create an OAuthClient in OpenShift that matches your deployment:

```bash
oc create -f - <<EOF
apiVersion: oauth.openshift.io/v1
kind: OAuthClient
metadata:
  name: mcp-gateway
grantMethod: auto
redirectURIs:
  - "https://mcp-gateway.default.svc:8081/oauth/callback"
  - "https://mcp-gateway.apps.<YOUR_CLUSTER_DOMAIN>/oauth/callback"
EOF
```

**Note**: Replace `<YOUR_CLUSTER_DOMAIN>` with your actual cluster domain. The redirect URIs should match where your service is accessible.

### Step 4: Deploy the Application

Apply the deployment:

```bash
oc apply -f examples/openshift-mcp-gateway-sidecar.yml
```

### Step 5: Expose the Service (Optional)

If you want to access the service from outside the cluster, create a Route:

```bash
oc create route edge mcp-gateway \
  --service=mcp-gateway \
  --port=oauth \
  --hostname=mcp-gateway.apps.<YOUR_CLUSTER_DOMAIN>
```

### Step 6: Update Environment Variables

After creating the Route, update the `OAUTH_AUTHORIZATION_SERVERS` environment variable in the deployment to use the Route URL:

```bash
oc set env deployment/mcp-gateway \
  -c mcp-shield \
  OAUTH_AUTHORIZATION_SERVERS="https://mcp-gateway.apps.<YOUR_CLUSTER_DOMAIN>"
```

## How It Works

1. **Main Container** (`mcp-broker-router`): Runs the MCP Gateway on port 8080
   - Handles MCP protocol requests at `/mcp` endpoint
   - Aggregates tools from multiple backend MCP servers
   - Routes MCP requests to appropriate backend servers
   - **Uses Authorization header from MCP Shield**: The router passes through the `Authorization` header from incoming requests (provided by MCP Shield) when initializing sessions with backend MCP servers
   - **Important**: Do NOT configure static credentials (`credentialEnvVar` or `KAGENTAI_*_CRED` env vars) for backend servers, as this would override the dynamic Authorization header from MCP Shield
   - Uses the user's OAuth token (from MCP Shield) for authentication with backend MCP servers

2. **MCP Shield Sidecar** (`mcp-shield`): Runs on port 8081 and handles:
   - OAuth discovery endpoints (`/.well-known/oauth-authorization-server`)
   - Client registration (`/oauth/register`)
   - OAuth start flow (`/oauth2/start`) with callback proxy support
   - OAuth callback (`/oauth/callback`) with redirect URI restoration
   - Token exchange (`/oauth/token`) with parameter filtering
   - MCP proxy (`/mcp`, `/mcp/`, `/`) forwarding to MCP Gateway's `/mcp` endpoint
   - **Forwards Authorization header**: Exchanges proxy tokens for real OAuth tokens and forwards them in the `Authorization` header to MCP Gateway

3. **Service**: Exposes both ports:
   - Port 8081 (oauth) - For OAuth endpoints and MCP client connections
   - Port 8080 (mcp) - For direct MCP Gateway access (optional, usually not exposed externally)

4. **Route** (optional): Exposes the service externally via OpenShift Route
   - Typically exposes port 8081 (MCP Shield)
   - Handles TLS termination
   - Provides public URL for OAuth flows

## Testing

Test the OAuth discovery endpoint:

```bash
# Get the service URL
SERVICE_URL=$(oc get route mcp-gateway -o jsonpath='{.spec.host}')

# Test OAuth discovery
curl https://${SERVICE_URL}/.well-known/oauth-authorization-server
```

Test the health check:

```bash
curl https://${SERVICE_URL}/healthz
```

Test the MCP Gateway endpoint (after OAuth authentication):

```bash
# This requires a valid OAuth token
curl -H "Authorization: Bearer <token>" https://${SERVICE_URL}/mcp
```

## Integration with MCP Gateway Features

MCP Shield works seamlessly with MCP Gateway's features:

- **Multiple Backend Servers**: MCP Shield authenticates requests, and MCP Gateway routes them to the appropriate backend MCP server
- **Tool Aggregation**: MCP Gateway aggregates tools from multiple servers, and MCP Shield ensures all requests are properly authenticated
- **Session Management**: MCP Gateway handles MCP sessions, while MCP Shield handles OAuth sessions
- **Virtual Servers**: MCP Gateway's virtual server feature works with MCP Shield's authentication

## Configuration Notes

- **MCP Gateway Config**: MCP Gateway requires a configuration file or ConfigMap. Ensure your MCP Gateway container has access to the necessary configuration.
- **Backend MCP Servers**: MCP Gateway connects to backend MCP servers. These servers may also need authentication configured separately.
- **Public Host**: MCP Gateway requires `--mcp-gateway-public-host` flag. This should match the hostname where MCP Shield is accessible.

### Backend MCP Server Configuration

**Critical**: MCP Gateway requires at least one backend MCP server to be configured in the `mcp-gateway-config` ConfigMap. Without backend servers, the gateway cannot forward tool calls and will return the error: "Kagenti MCP Broker doesn't forward tool calls".

To configure backend MCP servers, edit the ConfigMap and add server entries:

```bash
oc edit configmap mcp-gateway-config -n default
```

Example configuration for a Prometheus MCP server:

```yaml
servers:
  - name: prometheus
    url: http://prometheus-mcp-server.default.svc:8080/mcp
    toolPrefix: prometheus_
    enabled: true
    hostname: prometheus.mcp.local
```

After updating the ConfigMap, the MCP Gateway will automatically reload the configuration and discover tools from the backend servers.

### Authorization Header Forwarding

**Important**: MCP Shield forwards the Authorization header (with the real user OAuth token) to MCP Gateway. MCP Gateway's router passes through the Authorization header from incoming requests when initializing sessions with backend MCP servers.

To ensure MCP Gateway uses the Authorization header from MCP Shield:

1. **Do NOT set static credentials** for backend MCP servers in the MCP Gateway configuration:
   - Do NOT set `credentialEnvVar` in the server configuration
   - Do NOT set environment variables like `KAGENTAI_{MCP_NAME}_CRED`
   
2. **MCP Gateway will automatically use the Authorization header** from the incoming request (provided by MCP Shield) when connecting to backend MCP servers.

3. **If static credentials are set**, they will override the dynamic Authorization header from MCP Shield, which would break the OAuth flow.

Example configuration (correct):
```yaml
servers:
  - name: prometheus
    url: http://prometheus-mcp-server.default.svc:8080/mcp
    toolPrefix: prometheus_
    enabled: true
    hostname: prometheus.mcp.local
    # No credentialEnvVar - uses Authorization header from MCP Shield
```

Example configuration (incorrect - would override MCP Shield's token):
```yaml
servers:
  - name: prometheus
    url: http://prometheus-mcp-server.default.svc:8080/mcp
    toolPrefix: prometheus_
    enabled: true
    hostname: prometheus.mcp.local
    credentialEnvVar: PROMETHEUS_CRED  # ❌ Don't set this when using MCP Shield
```

