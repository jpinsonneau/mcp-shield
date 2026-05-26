# MCP Gateway integration

MCP Shield is often placed **in front of** [mcp-gateway](https://github.com/Kuadrant/mcp-gateway) so clients run OAuth against Shield while the gateway federates tools and routes `tools/call`. That interaction is discussed in [Kuadrant/mcp-gateway#414](https://github.com/Kuadrant/mcp-gateway/issues/414).

## Two modes

### 1. Direct tool routing (default)

When `MCP_BACKEND_URL` points at a gateway and `MCP_SHIELD_DIRECT_TOOL_ROUTING` is **enabled** (default), Shield discovers upstreams from the gateway `/status` endpoint and may send `tools/call` **directly** to upstream MCP servers for lower latency. Non–tool-call traffic still uses `MCP_BACKEND_URL`.

See [direct-tool-routing.md](./direct-tool-routing.md).

### 2. Through-gateway mode (compatibility)

Set:

```bash
export MCP_SHIELD_DIRECT_TOOL_ROUTING=false
```

Effects:

- Shield **does not** call the gateway `/status` for upstream discovery (no background discovery goroutines).
- **Every** MCP request, including `tools/call`, is proxied to `MCP_BACKEND_URL` / `MCP_BACKEND_PATH` only (after proxy-token → real token exchange).

Use this when you want **one hop** through mcp-gateway for all JSON-RPC (e.g. while gateway/router behaviour is improved upstream, or for simpler debugging). Trade-off: higher latency and full gateway load for tool execution.

## Credentials on the gateway

When Shield forwards the user’s **real** OpenShift token in `Authorization`, do **not** configure static backend credentials on the gateway that would override that header for those servers. The [mcp-gateway example](./examples/mcp-gateway.md) calls this out.

## Roadmap pointer

Longer term, mcp-gateway may reduce the need for direct routing by fixing session/routing when the gateway is addressed as a single MCP endpoint. Until then, **default remains direct routing**; **through-gateway** is opt-in via `MCP_SHIELD_DIRECT_TOOL_ROUTING=false`.

## OpenShift example (Route + optional Kuadrant)

See [examples/openshift-mcp-gateway-sidecar.yml](../examples/openshift-mcp-gateway-sidecar.yml): OpenShift Route to MCP Shield (`:8081`), `MCP_SHIELD_DIRECT_TOOL_ROUTING=false`, broker `OAUTH_*` env aligned with the public Route host, and a ConfigMap `mcp-gateway-kuadrant-authpolicy-example` holding an **optional** Kuadrant `AuthPolicy` fragment (OpenShift `issuerUrl`, path exclusions). Extract `data.authpolicy.yaml` and apply only if you use Istio Gateway + Kuadrant in front of the MCP listener; do not use that JWT policy on the same path where clients send Shield **proxy** tokens.
