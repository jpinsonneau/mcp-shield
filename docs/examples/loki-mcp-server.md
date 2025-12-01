# Deploying MCP Shield with Loki MCP Server

MCP Shield can also be deployed alongside the [Grafana Loki MCP Server](https://github.com/grafana/loki-mcp). An example deployment is provided in `examples/openshift-loki-sidecar.yml`.

## Quick Start (Automated)

The easiest way to deploy is using the provided script:

```bash
cd examples
./deploy-openshift-loki-sidecar.sh
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
./deploy-openshift-loki-sidecar.sh --namespace mcp

# Use a custom OAuth client ID
./deploy-openshift-loki-sidecar.sh --client-id my-loki-mcp-server

# Deploy without creating a Route
./deploy-openshift-loki-sidecar.sh --no-route

# Clean up deployment
./deploy-openshift-loki-sidecar.sh --cleanup
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

Edit `examples/openshift-loki-sidecar.yml` and replace `PLACEHOLDER` with your cluster domain:

```bash
# Replace PLACEHOLDER with your cluster domain
sed -i 's/PLACEHOLDER/your-cluster-domain.com/g' examples/openshift-loki-sidecar.yml
```

Also configure environment variables:
- **LOKI_URL**: Set to your Loki server URL (e.g., `https://loki-gateway.logging.svc:8080`)
- **LOKI_ORG_ID**: Optional, set if using multi-tenant Loki
- **LOKI_USERNAME/LOKI_PASSWORD**: Optional, for basic auth (if not using OAuth tokens)
- **LOKI_TOKEN**: Leave empty - MCP Shield will inject OAuth tokens via Authorization header

For the MCP Shield container, configure:
- `MCP_BACKEND_PATH` - **Important**: Set to `/stream` for Loki MCP server (Loki uses `/stream` for HTTP requests, `/mcp` is for SSE)
- `OAUTH_AUTHORIZATION_SERVERS` - Set to the public URL where MCP Shield is accessible
- `INSPECTOR_ORIGIN` - Set to the MCP Inspector origin URL (for CORS)
- `OAUTH_CLIENT_ID` - Set to match the OAuthClient name you'll create (default: `loki-mcp-server`)

### Step 3: Create the OAuth Client

Create an OAuthClient in OpenShift that matches your deployment:

```bash
oc create -f - <<EOF
apiVersion: oauth.openshift.io/v1
kind: OAuthClient
metadata:
  name: loki-mcp-server
grantMethod: auto
redirectURIs:
  - "https://loki-mcp-server.default.svc:8081/oauth/callback"
  - "https://loki-mcp-server.apps.<YOUR_CLUSTER_DOMAIN>/oauth/callback"
EOF
```

**Note**: Replace `<YOUR_CLUSTER_DOMAIN>` with your actual cluster domain.

### Step 4: Deploy the Application

Apply the deployment:

```bash
oc apply -f examples/openshift-loki-sidecar.yml
```

### Step 5: Configure Loki URL

Update the `LOKI_URL` environment variable to point to your Loki instance:

```bash
oc set env deployment/loki-mcp-server \
  -c loki-mcp-server \
  LOKI_URL="https://loki-gateway.logging.svc:8080"
```

### Step 6: Expose the Service (Optional)

If you want to access the service from outside the cluster, create a Route:

```bash
oc create route edge loki-mcp-server \
  --service=loki-mcp-server \
  --port=oauth \
  --hostname=loki-mcp-server.apps.<YOUR_CLUSTER_DOMAIN>
```

### Step 7: Update Environment Variables

After creating the Route, update the `OAUTH_AUTHORIZATION_SERVERS` environment variable in the deployment to use the Route URL:

```bash
oc set env deployment/loki-mcp-server \
  -c mcp-shield \
  OAUTH_AUTHORIZATION_SERVERS="https://loki-mcp-server.apps.<YOUR_CLUSTER_DOMAIN>"
```

## How It Works

1. **Main Container** (`loki-mcp-server`): Runs the Loki MCP server on port 8080
   - Handles MCP protocol requests
   - **Stateless operation**: Extracts Bearer token from `Authorization` header on each request
   - Uses the user's OAuth token to authenticate with Loki for each request
   - Queries Loki using user credentials from the token
   - **No ServiceAccount permissions needed** - all operations use the user's OAuth token
   - No session management - each request is independent
   - Exposes `/stream` endpoint for HTTP requests (Streamable HTTP)
   - Exposes `/mcp` endpoint for SSE (Server-Sent Events)

2. **MCP Shield Sidecar** (`mcp-shield`): Runs on port 8081 and handles:
   - OAuth discovery endpoints (`/.well-known/oauth-authorization-server`)
   - Client registration (`/oauth/register`)
   - OAuth start flow (`/oauth2/start`) with callback proxy support
   - OAuth callback (`/oauth/callback`) with redirect URI restoration
   - Token exchange (`/oauth/token`) with parameter filtering
   - MCP proxy (`/mcp`, `/mcp/`, `/`) forwarding to Loki MCP server's `/stream` endpoint
   - **sessionId injection**: Automatically injects `sessionId` into JSON-RPC requests (required by Loki MCP server)

3. **Service**: Exposes both ports:
   - Port 8081 (oauth) - For OAuth endpoints and MCP client connections
   - Port 8080 (mcp) - For direct MCP server access (optional, usually not exposed externally)

4. **Route** (optional): Exposes the service externally via OpenShift Route
   - Typically exposes port 8081 (MCP Shield)
   - Handles TLS termination
   - Provides public URL for OAuth flows

## Testing

Test the OAuth discovery endpoint:

```bash
# Get the service URL
SERVICE_URL=$(oc get route loki-mcp-server -o jsonpath='{.spec.host}')

# Test OAuth discovery
curl https://${SERVICE_URL}/.well-known/oauth-authorization-server
```

Test the health check:

```bash
curl https://${SERVICE_URL}/healthz
```

