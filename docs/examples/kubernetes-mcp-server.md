# Deploying MCP Shield with Kubernetes MCP Server

MCP Shield can be deployed alongside the [Kubernetes MCP Server](https://github.com/containers/kubernetes-mcp-server). While kubernetes-mcp-server can proxy OAuth metadata to an external authorization server, it does not implement the full OAuth flow. MCP Shield provides discovery, registration, authorize redirect, callback, and token exchange for MCP clients (Inspector, agentic CLI tools, and similar).

The example uses **`cluster_auth_mode = "passthrough"`** so every tool call uses the **user's OpenShift access token** that Shield forwards in `Authorization: Bearer …`. Do **not** enable `require_oauth` on the server when Shield is in front.

An example deployment is provided in `examples/openshift-kubernetes-mcp-server-sidecar.yml` (ConfigMap + Deployment + Service + Route).

For Helm strategy (kubernetes-mcp-server chart vs a future Shield chart), see [Helm deployment planning](../helm-deployment.md).

## Quick Start (Automated)

The easiest way to deploy is using the provided script:

```bash
cd examples
./deploy-openshift-kubernetes-mcp-server-sidecar.sh
```

This script will:

1. Detect your OpenShift cluster domain
2. Replace `PLACEHOLDER` in the YAML with that domain
3. Create the OAuthClient (if missing) and validate redirect URIs
4. Deploy the application (ConfigMap, Deployment, Service, Route)
5. Create a Route with `oc create route` only if the manifest Route was not applied
6. Set `OAUTH_AUTHORIZATION_SERVERS` on the Shield container to the public Route URL

**Options:**

```bash
# Deploy to a specific namespace
./deploy-openshift-kubernetes-mcp-server-sidecar.sh --namespace mcp

# Use a custom OAuth client ID (must match OAuthClient metadata.name)
./deploy-openshift-kubernetes-mcp-server-sidecar.sh --client-id my-kubernetes-mcp-server

# Custom images (e.g. kubernetes-mcp-server build that includes netobserv)
export KUBERNETES_MCP_SERVER_IMAGE=quay.io/<you>/kubernetes_mcp_server:netobserv-dev
export MCP_SHIELD_IMAGE=quay.io/<you>/mcp-shield:dev
./deploy-openshift-kubernetes-mcp-server-sidecar.sh

# Deploy without creating an extra Route (manifest already includes a Route)
./deploy-openshift-kubernetes-mcp-server-sidecar.sh --no-route

# Clean up deployment
./deploy-openshift-kubernetes-mcp-server-sidecar.sh --cleanup
```

**Environment variables** (used by the script):

| Variable | Purpose |
|----------|---------|
| `CLUSTER_DOMAIN` | Override auto-detected apps domain |
| `KUBERNETES_MCP_SERVER_IMAGE` | Main container image |
| `MCP_SHIELD_IMAGE` | Sidecar image |

## Manual Deployment

If you prefer to deploy manually, follow these steps:

### Step 1: Get Your OpenShift Cluster Domain

Determine your OpenShift cluster domain (the part after `*.apps.`):

```bash
# From the console route
oc get route console -n openshift-console -o jsonpath='{.spec.host}' | sed 's/console-openshift-console\.//' | sed 's/^apps\.//'

# Or from ingress config
oc get ingress.config cluster -o jsonpath='{.spec.domain}' | sed 's/^apps\.//'
```

Example: if the console host is `console-openshift-console.apps.ostest.test.metalkube.org`, the domain is `ostest.test.metalkube.org`.

### Step 2: Update the Example Deployment

Edit `examples/openshift-kubernetes-mcp-server-sidecar.yml` and replace every **`PLACEHOLDER`** with your cluster domain:

```bash
# Replace PLACEHOLDER with your cluster domain (run from repo root or adjust paths)
sed -i 's/PLACEHOLDER/ostest.test.metalkube.org/g' examples/openshift-kubernetes-mcp-server-sidecar.yml
```

This updates:

- Route host: `kubernetes-mcp-server.apps.<domain>`
- Shield `OAUTH_AUTHORIZATION_SERVERS`: `https://kubernetes-mcp-server.apps.<domain>`

Adjust **namespace**, **service name**, and **image** if needed before applying.

**ConfigMap (`kubernetes-mcp-server-config`)** — server settings for Shield + passthrough:

```toml
port = "8080"
toolsets = ["core", "config"]
cluster_auth_mode = "passthrough"
# require_oauth must stay false (default) when MCP Shield terminates OAuth for clients.
```

| Setting | With MCP Shield |
|---------|-----------------|
| `cluster_auth_mode` | **`passthrough`** — use the user's token from Shield |
| `require_oauth` | **`false`** (default) — do not enable |
| `cluster_auth_mode: kubeconfig` | **Do not use** — would use the pod SA instead of the user |
| ClusterRoleBinding on the pod SA | **Not required** for API authorization (user token carries RBAC) |

**NetObserv:** the published `quay.io/containers/kubernetes_mcp_server` image may not include the `netobserv` toolset yet. Use a custom image and extend `config.toml`, for example:

```toml
toolsets = ["core", "config", "netobserv"]

[toolset_configs.netobserv]
namespace = "netobserv"
service = "netobserv-plugin"
port = 9001
```

**MCP Shield container** environment (also set in the example YAML):

| Variable | Value |
|----------|--------|
| `OAUTH_AUTHORIZATION_SERVERS` | Public URL of Shield (same host as the Route), e.g. `https://kubernetes-mcp-server.apps.<YOUR_CLUSTER_DOMAIN>` |
| `OAUTH_CLIENT_ID` | Must match `OAuthClient` name (default: `kubernetes-mcp-server`) |
| `OPENSHIFT_OAUTH_TOKEN_URL` | `https://oauth-openshift.openshift-authentication.svc.cluster.local/oauth/token` (recommended in-cluster) |
| `MCP_BACKEND_URL` | `http://localhost:8080` (main container in the same pod) |
| `MCP_BACKEND_PATH` | `/mcp` |
| `INSPECTOR_ORIGIN` | `http://localhost:6274` (MCP Inspector default; adjust for CORS if needed) |
| `OAUTH_REDIRECT_URIS` | Optional comma-separated extra redirect URIs |

### Step 3: Create the OAuth Client

Create an OAuthClient in OpenShift that matches your deployment (cluster-scoped resource):

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

**Note:**

- Replace `<YOUR_CLUSTER_DOMAIN>` and adjust `default` if you use another namespace.
- Replace `kubernetes-mcp-server` in the hostnames if you changed the service name.
- If the OAuthClient already exists, ensure both redirect URIs are present (the deploy script checks this).

**MCP Inspector / localhost:** Shield can proxy loopback redirect URIs (`http://localhost:…`, `http://127.0.0.1:…`) via its fixed `/oauth/callback`. You do not need to register every dynamic Inspector port on the OAuthClient.

### Step 4: Deploy the Application

Apply the manifest:

```bash
oc apply -f examples/openshift-kubernetes-mcp-server-sidecar.yml
```

Wait for the pod:

```bash
oc wait --for=condition=available deployment/kubernetes-mcp-server -n default --timeout=300s
```

### Step 5: Expose the Service (Optional)

The example manifest includes an OpenShift **Route** targeting Service port **`oauth`** (8081). If you removed it or deploy without that section, create a Route manually:

```bash
oc create route edge kubernetes-mcp-server \
  --service=kubernetes-mcp-server \
  --port=oauth \
  --hostname=kubernetes-mcp-server.apps.<YOUR_CLUSTER_DOMAIN>
```

Clients must use **port 8081 (Shield)**, not 8080 (backend only).

### Step 6: Update Environment Variables

If the Route host differs from what is in the YAML, set Shield's public base URL:

```bash
oc set env deployment/kubernetes-mcp-server \
  -c mcp-shield \
  OAUTH_AUTHORIZATION_SERVERS="https://kubernetes-mcp-server.apps.<YOUR_CLUSTER_DOMAIN>"
```

### Step 7: Verify configuration

Confirm passthrough config is mounted:

```bash
oc get configmap kubernetes-mcp-server-config -o jsonpath='{.data.config\.toml}'
```

Confirm the main container uses it:

```bash
oc get deployment kubernetes-mcp-server -o jsonpath='{.spec.template.spec.containers[?(@.name=="kubernetes-mcp-server")].args}'
```

## How It Works

1. **Main container** (`kubernetes-mcp-server`): Runs on port **8080**
   - Loads `config.toml` with `cluster_auth_mode = "passthrough"`
   - Handles MCP at `/mcp`
   - Extracts `Authorization: Bearer` on each request and uses that token for Kubernetes API and toolset backends (e.g. NetObserv plugin)
   - **No ClusterRoleBinding required** for user-scoped access — OpenShift RBAC applies to the user's token
   - Does not run the browser OAuth flow when `require_oauth` is false

2. **MCP Shield sidecar** (`mcp-shield`): Runs on port **8081**
   - OAuth discovery (`/.well-known/oauth-authorization-server`, protected resource metadata)
   - Client registration (`/oauth/register`)
   - OAuth start (`/oauth2/start`) and callback (`/oauth/callback`) with loopback redirect handling
   - Token exchange (`/oauth/token`) toward OpenShift
   - MCP proxy to `http://localhost:8080/mcp` after exchanging proxy tokens for real access tokens

3. **Service**
   - Port **8081** (`oauth`) — MCP and OAuth for external clients
   - Port **8080** (`mcp`) — direct backend access (optional, usually not exposed on the Route)

4. **Route**
   - Terminates TLS at the edge
   - Forwards to Service port **oauth** (8081)
   - Public URL used as `OAUTH_AUTHORIZATION_SERVERS`

## This deployment vs Helm (ServiceAccount)

If you use **`examples/openshift-kubernetes-mcp-server-sidecar.yml`** (not the kubernetes-mcp-server Helm `values-openshift-netobserv.yaml` example):

| | Sidecar YAML (this doc) | Helm NetObserv example |
|---|------------------------|-------------------------|
| MCP URL | `https://<route>/mcp` on **8081** (Shield) | Often **8080** (server only) |
| Auth | User OAuth via Shield → **passthrough** | Pod **ServiceAccount** (`kubeconfig`) |
| NetObserv RBAC | **Your** OpenShift user | Shared SA |

Do not mix them: uninstall the Helm release if you switch to this manifest, or you will have two deployments and confusing auth behavior.

### Verify the user token is used (not the SA)

1. Connect the MCP client to **`https://<route-host>/mcp`** (Shield), complete **OAuth**.
2. Call `namespaces_list` — results should match `oc auth can-i --list` for **your** user, not a generic cluster-wide SA view.
3. Enable verbose logs and confirm Bearer passthrough (no silent SA fallback):

```bash
oc logs -n <namespace> deployment/kubernetes-mcp-server -c kubernetes-mcp-server --tail=200 | grep -i bearer
# Or run the server with --log-level=4 in the Deployment args
```

If OAuth was skipped, passthrough mode **falls back to the ServiceAccount** and NetObserv calls use the SA token instead of yours — fix the client URL and OAuth flow, not NetObserv RBAC on the SA.

NetObserv plugin calls still use `rest.Config.BearerToken` from the **derived** client (user token when OAuth succeeded). Your user needs RBAC to read flows in the target namespaces (same as in the OpenShift console NetObserv UI).

**NetObserv NetworkPolicy:** the operator’s default policy does **not** allow `default` → `netobserv-plugin:9001`. If MCP runs in `default`, patch the FlowCollector:

```bash
oc patch flowcollector cluster --type=merge -p '{"spec":{"networkPolicy":{"additionalNamespaces":["default"]}}}'
```

See [kubernetes-mcp-server NetObserv troubleshooting](https://github.com/containers/kubernetes-mcp-server/blob/main/docs/NETOBSERV.md#connection-timeout-from-another-namespace-curl-http_code000).

## Testing

Test OAuth discovery and health:

```bash
SERVICE_URL=$(oc get route kubernetes-mcp-server -o jsonpath='{.spec.host}')

curl -sk "https://${SERVICE_URL}/healthz"

curl -sk "https://${SERVICE_URL}/.well-known/oauth-authorization-server" | jq .
```

**MCP Inspector**

1. Port-forward if you have no Route: `oc port-forward svc/kubernetes-mcp-server 8081:8081`
2. Transport: **Streamable HTTP**
3. URL: `https://${SERVICE_URL}/mcp` or `http://127.0.0.1:8081/mcp`
4. Complete OAuth (client id = your `OAuthClient` name)
5. Call `namespaces_list`, then NetObserv tools if enabled in `config.toml`

Results should match **your** OpenShift user permissions, not a shared ServiceAccount.

## Compared to Helm without MCP Shield

The [kubernetes-mcp-server Helm chart](https://github.com/containers/kubernetes-mcp-server/tree/main/charts/kubernetes-mcp-server) can deploy with **`cluster_auth_mode: kubeconfig`** and a pod ServiceAccount for a **shared** cluster identity (no per-user login). That pattern does not use MCP Shield.

Use **Shield + passthrough** when each MCP user should sign in with **their own** OpenShift account.

## Related documentation

- [OpenShift user pattern](../openshift-user-pattern.md)
- [Examples index](../../examples/README.md)
- [Helm deployment planning](../helm-deployment.md)
