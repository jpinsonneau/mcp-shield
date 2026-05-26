# OpenShift-oriented examples

YAML snippets for common setups. Replace image pulls, namespaces, hostnames, and `OAuthClient` names with your cluster values.

| File | Use case |
|------|----------|
| [openshift-prometheus-sidecar.yml](./openshift-prometheus-sidecar.yml) | Shield + prometheus-mcp-server |
| [openshift-loki-sidecar.yml](./openshift-loki-sidecar.yml) | Shield + loki-mcp |
| [openshift-kubernetes-mcp-server-sidecar.yml](./openshift-kubernetes-mcp-server-sidecar.yml) | Shield + kubernetes-mcp-server (`cluster_auth_mode = passthrough`, ConfigMap, Route → :8081) |
| [openshift-mcp-gateway-sidecar.yml](./openshift-mcp-gateway-sidecar.yml) | Shield + mcp-gateway in the same pod (`MCP_SHIELD_DIRECT_TOOL_ROUTING=false`), Route to Shield :8081, broker `OAUTH_*` env, optional Kuadrant AuthPolicy example in ConfigMap |

Narrative guides live under [docs/examples/](../docs/examples/). The overall OpenShift pattern is described in [docs/openshift-user-pattern.md](../docs/openshift-user-pattern.md).

Helm strategy (extend kubernetes-mcp-server chart vs Shield-only chart): [docs/helm-deployment.md](../docs/helm-deployment.md).
