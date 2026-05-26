# OpenShift pattern: user-scoped MCP (Prometheus / Loki)

This is the opinionated layout MCP Shield is built for: **OpenShift users authenticate once**, MCP clients get a **proxy token** (or you rely on the same flow), and **Prometheus MCP** or **Loki MCP** receive the **real OpenShift access token** on each request so metrics and logs stay scoped to that user.

## What you deploy

1. **MCP Shield** (usually a sidecar or separate Deployment in front of the MCP HTTP surface).
2. **One or more MCP servers** that understand `Authorization: Bearer <token>` and call cluster observability APIs with that token (e.g. [prometheus-mcp-server](https://github.com/tjhop/prometheus-mcp-server), [loki-mcp](https://github.com/grafana/loki-mcp)).
3. **Optional [mcp-gateway](https://github.com/Kuadrant/mcp-gateway)** when you need multiple backends federated behind one URL; Shield still terminates OAuth and forwards the real token.

## OpenShift objects (minimum)

- **Route (or Ingress)** to MCP Shield’s public URL — used as `OAUTH_AUTHORIZATION_SERVERS` and as the browser callback host.
- **`OAuthClient`** whose `redirectURIs` include Shield’s fixed callback, e.g. `https://<shield-route>/oauth/callback`, and whose `metadata.name` matches `OAUTH_CLIENT_ID` (default in Shield is geared toward prometheus-mcp-server; override per app).
- **Pod(s)** running Shield + MCP server (or Shield + gateway), with `MCP_BACKEND_URL` pointing at the MCP HTTP endpoint inside the pod/cluster.

Shield implements discovery, registration, authorize redirect, callback, and token exchange quirks for OpenShift (`resource=undefined`, `redirect_uri`, Basic auth to the token endpoint). See the [architecture section in README](../README.md).

## Environment checklist

| Variable | Role |
|----------|------|
| `OAUTH_AUTHORIZATION_SERVERS` | Public base URL of Shield (must match Route). |
| `MCP_BACKEND_URL` | HTTP origin for MCP (single server or mcp-gateway broker). |
| `MCP_BACKEND_PATH` | `/mcp` (Prometheus, Kubernetes MCP) or `/stream` (Loki HTTP). |
| `OAUTH_CLIENT_ID` | Must match `OAuthClient` name if you use OpenShift’s integrated OAuth. |
| `INSPECTOR_ORIGIN` | Optional; tighten CORS instead of `*`. |
| `MCP_SHIELD_DIRECT_TOOL_ROUTING` | Optional; set `false` to force all MCP via `MCP_BACKEND_URL` when using mcp-gateway ([gateway integration](./mcp-gateway-integration.md)). |

For **kubernetes-mcp-server**, set `cluster_auth_mode = "passthrough"` and `require_oauth = false` in the server `config.toml` ([kubernetes example](./examples/kubernetes-mcp-server.md)).

## Copy-paste examples

- Prometheus: [examples/openshift-prometheus-sidecar.yml](../examples/openshift-prometheus-sidecar.yml) and [docs/examples/prometheus-mcp-server.md](./examples/prometheus-mcp-server.md).
- Loki: [examples/openshift-loki-sidecar.yml](../examples/openshift-loki-sidecar.yml) and [docs/examples/loki-mcp-server.md](./examples/loki-mcp-server.md).
- MCP Gateway in front: [examples/openshift-mcp-gateway-sidecar.yml](../examples/openshift-mcp-gateway-sidecar.yml) and [docs/examples/mcp-gateway.md](./examples/mcp-gateway.md).

## Security note

Proxy tokens limit what a compromised **client cache** can do; the **upstream MCP server** still receives the **real** bearer token for Prometheus/Loki user filtering. Lock down Routes, use short TTLs (`PROXY_TOKEN_TTL`), and scope `OAuthClient` grants to what those tools need.
