# Deploying MCP Shield with Kubernetes MCP Server

MCP Shield can also be deployed alongside the [Kubernetes MCP Server](https://github.com/containers/kubernetes-mcp-server). While kubernetes-mcp-server supports external OAuth (proxying well-known endpoints to an external authorization server), it does not implement the complete OAuth flow. MCP Shield provides the full OAuth 2.0 flow implementation needed for MCP clients like MCP Inspector and agentic CLI clients.

An example deployment is provided in `examples/openshift-kubernetes-mcp-server-sidecar.yml`.

## Quick Start (Automated)

The easiest way to deploy is using the provided script:

```bash
cd examples
./deploy-openshift-kubernetes-mcp-server-sidecar.sh
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
./deploy-openshift-kubernetes-mcp-server-sidecar.sh --namespace mcp

# Use a custom OAuth client ID
./deploy-openshift-kubernetes-mcp-server-sidecar.sh --client-id my-kubernetes-mcp-server

# Deploy without creating a Route
./deploy-openshift-kubernetes-mcp-server-sidecar.sh --no-route

# Clean up deployment
./deploy-openshift-kubernetes-mcp-server-sidecar.sh --cleanup
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

Edit `examples/openshift-kubernetes-mcp-server-sidecar.yml` and replace `PLACEHOLDER` with your cluster domain:

```bash
# Replace PLACEHOLDER with your cluster domain
sed -i 's/PLACEHOLDER/your-cluster-domain.com/g' examples/openshift-kubernetes-mcp-server-sidecar.yml
```

Also configure environment variables in the MCP Shield container:
- `OAUTH_AUTHORIZATION_SERVERS` - Set to the public URL where MCP Shield is accessible
- `INSPECTOR_ORIGIN` - Set to the MCP Inspector origin URL (for CORS)
- `OAUTH_CLIENT_ID` - Set to match the OAuthClient name you'll create (default: `kubernetes-mcp-server`)
- `OAUTH_REDIRECT_URIS` - Optional: comma-separated list of additional redirect URIs
- `MCP_BACKEND_PATH` - Set to `/mcp` for Kubernetes MCP server (this is the default)

**Important**: kubernetes-mcp-server uses Bearer tokens from the Authorization header (user's OAuth token) for all Kubernetes API operations, not the ServiceAccount token. The ServiceAccount is only needed for the pod to run. All user permissions come from their OpenShift OAuth token, so no ClusterRole/ClusterRoleBinding is needed.

### Step 3: Create the OAuth Client

Create an OAuthClient in OpenShift that matches your deployment:

```bash
oc create -f - <<EOF
apiVersion: oauth.openshift.io/v1
kind: OAuthClient
metadata:
  name: kubernetes-mcp-server
grantMethod: auto
redirectURIs:
  - "https://kubernetes-mcp-server.default.svc:8081/oauth/callback"
  - "https://kubernetes-mcp-server.apps.<YOUR_CLUSTER_DOMAIN>/oauth/callback"
EOF
```

**Note**: Replace `<YOUR_CLUSTER_DOMAIN>` with your actual cluster domain.

### Step 4: Deploy the Application

Apply the deployment:

```bash
oc apply -f examples/openshift-kubernetes-mcp-server-sidecar.yml
```

### Step 5: Expose the Service (Optional)

If you want to access the service from outside the cluster, create a Route:

```bash
oc create route edge kubernetes-mcp-server \
  --service=kubernetes-mcp-server \
  --port=oauth \
  --hostname=kubernetes-mcp-server.apps.<YOUR_CLUSTER_DOMAIN>
```

### Step 6: Update Environment Variables

After creating the Route, update the `OAUTH_AUTHORIZATION_SERVERS` environment variable in the deployment to use the Route URL:

```bash
oc set env deployment/kubernetes-mcp-server \
  -c mcp-shield \
  OAUTH_AUTHORIZATION_SERVERS="https://kubernetes-mcp-server.apps.<YOUR_CLUSTER_DOMAIN>"
```

## How It Works

1. **Main Container** (`kubernetes-mcp-server`): Runs the Kubernetes MCP server on port 8080
   - Handles MCP protocol requests
   - **Stateless operation**: Extracts Bearer token from `Authorization` header on each request
   - Uses the user's OAuth token to authenticate with Kubernetes API server for each request
   - Queries Kubernetes resources using user credentials from the token
   - **No ServiceAccount permissions needed** - all operations use the user's OAuth token
   - No session management - each request is independent
   - Exposes `/mcp` endpoint for HTTP requests

2. **MCP Shield Sidecar** (`mcp-shield`): Runs on port 8081 and handles:
   - OAuth discovery endpoints (`/.well-known/oauth-authorization-server`)
   - Client registration (`/oauth/register`)
   - OAuth start flow (`/oauth2/start`) with callback proxy support
   - OAuth callback (`/oauth/callback`) with redirect URI restoration
   - Token exchange (`/oauth/token`) with parameter filtering
   - MCP proxy (`/mcp`, `/mcp/`, `/`) forwarding to Kubernetes MCP server's `/mcp` endpoint

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
SERVICE_URL=$(oc get route kubernetes-mcp-server -o jsonpath='{.spec.host}')

# Test OAuth discovery
curl https://${SERVICE_URL}/.well-known/oauth-authorization-server
```

Test the health check:

```bash
curl https://${SERVICE_URL}/healthz
```

