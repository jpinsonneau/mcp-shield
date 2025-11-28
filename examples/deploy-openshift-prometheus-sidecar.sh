#!/bin/bash

# Deploy Prometheus MCP Server with MCP Shield Sidecar on OpenShift
# This script automates the deployment process including OAuth client creation
#
# Usage:
#   ./deploy-openshift-prometheus-sidecar.sh                    # Deploy with default settings
#   ./deploy-openshift-prometheus-sidecar.sh --namespace mcp    # Deploy to specific namespace
#   ./deploy-openshift-prometheus-sidecar.sh --cleanup          # Clean up deployment
#   ./deploy-openshift-prometheus-sidecar.sh --help             # Show help

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
NAMESPACE="default"
OAUTH_CLIENT_ID="prometheus-mcp-server"
SERVICE_NAME="prometheus-mcp-server"
MCP_SHIELD_IMAGE="${MCP_SHIELD_IMAGE:-quay.io/jpinsonn/mcp-shield:dev}"
CREATE_ROUTE=true

# Function to print colored output
print_status() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

print_warning() {
    printf "${YELLOW}[WARNING]${NC} %s\n" "$1"
}

print_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

print_step() {
    printf "${BLUE}[STEP]${NC} %s\n" "$1"
}

# Get OpenShift cluster domain
get_cluster_domain() {
    print_status "Detecting OpenShift cluster domain..."
    
    # Try to get the cluster domain from the console route
    CLUSTER_DOMAIN=$(oc get route console -n openshift-console -o jsonpath='{.spec.host}' 2>/dev/null | sed 's/console-openshift-console\.//' | sed 's/^apps\.//' || echo "")
    
    if [ -z "$CLUSTER_DOMAIN" ]; then
        # Fallback: try to get from ingress config
        CLUSTER_DOMAIN=$(oc get ingress.config cluster -o jsonpath='{.spec.domain}' 2>/dev/null | sed 's/^apps\.//' || echo "")
    fi
    
    if [ -z "$CLUSTER_DOMAIN" ]; then
        print_error "Could not detect OpenShift cluster domain. Please set CLUSTER_DOMAIN environment variable."
        print_status "Example: export CLUSTER_DOMAIN=apps.openshift.example.com"
        exit 1
    fi
    
    print_status "Detected cluster domain: $CLUSTER_DOMAIN"
    export CLUSTER_DOMAIN
}

# Replace placeholders in YAML files
replace_placeholders() {
    print_status "Replacing placeholders with cluster domain..."
    
    # Create namespace if it doesn't exist
    if ! oc get ns "$NAMESPACE" >/dev/null 2>&1; then
        print_status "Creating namespace $NAMESPACE..."
        oc create namespace "$NAMESPACE" >/dev/null
    fi
    
    # Create temporary file with replaced placeholders
    sed "s/PLACEHOLDER/$CLUSTER_DOMAIN/g" openshift-prometheus-sidecar.yml > /tmp/openshift-prometheus-sidecar.yml
    
    # Replace service name and namespace if needed
    if [ "$NAMESPACE" != "default" ] || [ "$SERVICE_NAME" != "prometheus-mcp-server" ]; then
        sed -i "s/namespace: default/namespace: $NAMESPACE/g" /tmp/openshift-prometheus-sidecar.yml
        sed -i "s/name: prometheus-mcp-server/name: $SERVICE_NAME/g" /tmp/openshift-prometheus-sidecar.yml
        sed -i "s/app: prometheus-mcp-server/app: $SERVICE_NAME/g" /tmp/openshift-prometheus-sidecar.yml
    fi
    
    # Replace MCP Shield image if custom image provided
    if [ "$MCP_SHIELD_IMAGE" != "quay.io/jpinsonn/mcp-shield:dev" ]; then
        sed -i "s|quay.io/jpinsonn/mcp-shield:dev|$MCP_SHIELD_IMAGE|g" /tmp/openshift-prometheus-sidecar.yml
    fi
    
    print_status "Placeholders replaced successfully."
}

# Create OAuth Client
create_oauth_client() {
    print_step "Creating OAuth Client..."
    
    # Check if OAuthClient already exists
    if oc get oauthclient "$OAUTH_CLIENT_ID" >/dev/null 2>&1; then
        print_warning "OAuthClient '$OAUTH_CLIENT_ID' already exists. Skipping creation."
        print_status "If you need to update it, delete it first: oc delete oauthclient $OAUTH_CLIENT_ID"
        return
    fi
    
    # Build redirect URIs
    REDIRECT_URIS=(
        "https://${SERVICE_NAME}.${NAMESPACE}.svc:8081/oauth/callback"
        "https://${SERVICE_NAME}.apps.${CLUSTER_DOMAIN}/oauth/callback"
    )
    
    # Create OAuthClient
    oc create -f - <<EOF
apiVersion: oauth.openshift.io/v1
kind: OAuthClient
metadata:
  name: $OAUTH_CLIENT_ID
grantMethod: auto
redirectURIs:
$(printf '  - "%s"\n' "${REDIRECT_URIS[@]}")
EOF
    
    print_status "OAuthClient '$OAUTH_CLIENT_ID' created successfully."
}

# Deploy the application
deploy_application() {
    print_step "Deploying application..."
    
    # Apply the deployment
    oc apply -f /tmp/openshift-prometheus-sidecar.yml
    
    # Wait for deployment to be ready
    print_status "Waiting for deployment to be ready..."
    oc wait --for=condition=available --timeout=300s deployment/"$SERVICE_NAME" -n "$NAMESPACE" || {
        print_error "Deployment failed or timed out."
        print_status "Check pod status: oc get pods -n $NAMESPACE -l app=$SERVICE_NAME"
        exit 1
    }
    
    print_status "Application deployed successfully."
}

# Create Route
create_route() {
    if [ "$CREATE_ROUTE" != "true" ]; then
        return
    fi
    
    print_step "Creating Route..."
    
    # Check if route already exists
    if oc get route "$SERVICE_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
        print_warning "Route '$SERVICE_NAME' already exists. Skipping creation."
        return
    fi
    
    # Create route
    oc create route edge "$SERVICE_NAME" \
        --service="$SERVICE_NAME" \
        --port=oauth \
        --hostname="${SERVICE_NAME}.apps.${CLUSTER_DOMAIN}" \
        -n "$NAMESPACE"
    
    print_status "Route created successfully."
    
    # Update environment variable with Route URL
    print_step "Updating OAUTH_AUTHORIZATION_SERVERS environment variable..."
    oc set env deployment/"$SERVICE_NAME" \
        -c mcp-shield \
        -n "$NAMESPACE" \
        OAUTH_AUTHORIZATION_SERVERS="https://${SERVICE_NAME}.apps.${CLUSTER_DOMAIN}"
    
    print_status "Environment variable updated."
}

# Get deployment information
get_deployment_info() {
    print_status "Getting deployment information..."
    
    # Get Route URL
    ROUTE_URL=$(oc get route "$SERVICE_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.host}' 2>/dev/null || echo "")
    
    if [ -n "$ROUTE_URL" ]; then
        print_status ""
        print_status "═══════════════════════════════════════════════════════════"
        print_status "Deployment Information:"
        print_status "═══════════════════════════════════════════════════════════"
        print_status "Service URL: https://${ROUTE_URL}"
        print_status "OAuth Discovery: https://${ROUTE_URL}/.well-known/oauth-authorization-server"
        print_status "OAuth Register: https://${ROUTE_URL}/oauth/register"
        print_status "Health Check: https://${ROUTE_URL}/healthz"
        print_status ""
        print_status "OAuth Client ID: $OAUTH_CLIENT_ID"
        print_status "Namespace: $NAMESPACE"
        print_status "═══════════════════════════════════════════════════════════"
    else
        print_warning "Route not found. Service may not be accessible from outside the cluster."
        print_status "Create a route manually or use port-forward:"
        print_status "  oc port-forward -n $NAMESPACE service/$SERVICE_NAME 8081:8081"
    fi
    
    # Show pod status
    print_status ""
    print_status "Pod status:"
    oc get pods -n "$NAMESPACE" -l app="$SERVICE_NAME" -o wide || true
}

# Cleanup function
cleanup() {
    print_status "Cleaning up temporary files..."
    rm -f /tmp/openshift-prometheus-sidecar.yml
}

# Cleanup deployment
cleanup_deployment() {
    print_status "Cleaning up deployment..."
    
    # Delete deployment
    oc delete deployment "$SERVICE_NAME" -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true
    
    # Delete service
    oc delete service "$SERVICE_NAME" -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true
    
    # Delete route
    oc delete route "$SERVICE_NAME" -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true
    
    # Delete configmap
    oc delete configmap "$SERVICE_NAME" -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true
    
    # Delete secret
    oc delete secret "${SERVICE_NAME}-oauth" -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true
    
    # Delete service account
    oc delete serviceaccount "$SERVICE_NAME" -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true
    
    # Delete OAuthClient
    print_status "Deleting OAuthClient..."
    oc delete oauthclient "$OAUTH_CLIENT_ID" --ignore-not-found=true 2>/dev/null || true
    
    # Clean up temporary files
    cleanup
    
    print_status "Cleanup completed successfully!"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v oc &> /dev/null; then
        print_error "oc command not found. Please install the OpenShift CLI."
        exit 1
    fi
    
    if ! oc whoami &> /dev/null; then
        print_error "Not logged in to OpenShift. Please run 'oc login' first."
        exit 1
    fi
    
    # Check if we're in the examples directory
    if [ ! -f "openshift-prometheus-sidecar.yml" ]; then
        print_error "openshift-prometheus-sidecar.yml not found in current directory."
        print_status "Please run this script from the examples directory:"
        print_status "  cd examples && ./deploy-openshift-prometheus-sidecar.sh"
        exit 1
    fi
    
    print_status "Prerequisites check passed."
}

# Main deployment function
main() {
    print_status "Starting Prometheus MCP Server with MCP Shield sidecar deployment..."
    print_status ""
    
    check_prerequisites
    get_cluster_domain
    replace_placeholders
    create_oauth_client
    deploy_application
    create_route
    get_deployment_info
    cleanup
    
    print_status ""
    print_status "Deployment completed successfully!"
    print_status ""
    print_status "Next steps:"
    print_status "1. Verify the deployment: oc get pods -n $NAMESPACE -l app=$SERVICE_NAME"
    print_status "2. Check logs: oc logs -n $NAMESPACE deployment/$SERVICE_NAME -c mcp-shield"
    print_status "3. Test OAuth discovery: curl https://${SERVICE_NAME}.apps.${CLUSTER_DOMAIN}/.well-known/oauth-authorization-server"
}

# Show usage information
show_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --namespace NAME          Namespace to deploy to (default: default)
  --client-id ID            OAuth client ID (default: prometheus-mcp-server)
  --service-name NAME       Service name (default: prometheus-mcp-server)
  --mcp-shield-image IMG     MCP Shield image (default: quay.io/jpinsonn/mcp-shield:dev)
  --no-route                Don't create a Route (default: create route)
  --cleanup                 Clean up the deployment
  --help                    Show this help message

Environment Variables:
  CLUSTER_DOMAIN            Override cluster domain detection

Examples:
  $0                                    # Deploy with defaults
  $0 --namespace mcp                    # Deploy to mcp namespace
  $0 --client-id my-mcp-server          # Use custom OAuth client ID
  $0 --no-route                         # Deploy without creating Route
  $0 --cleanup                           # Clean up deployment
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --client-id)
            OAUTH_CLIENT_ID="$2"
            shift 2
            ;;
        --service-name)
            SERVICE_NAME="$2"
            shift 2
            ;;
        --mcp-shield-image)
            MCP_SHIELD_IMAGE="$2"
            shift 2
            ;;
        --no-route)
            CREATE_ROUTE=false
            shift
            ;;
        --cleanup)
            cleanup_deployment
            exit 0
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Run main function
main

