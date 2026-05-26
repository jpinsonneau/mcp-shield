#!/bin/bash

# Setup OpenShift test users using htpasswd
# This script creates 3 test users and configures OpenShift to use htpasswd authentication
#
# Usage:
#   ./setup-openshift-test-users.sh                    # Create users with default passwords
#   ./setup-openshift-test-users.sh --cleanup          # Remove users and htpasswd identity provider
#   ./setup-openshift-test-users.sh --help             # Show help

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
SECRET_NAME="htpasswd-secret"
IDENTITY_PROVIDER_NAME="htpasswd"
NAMESPACE="openshift-config"
HTPASSWD_FILE="/tmp/htpasswd"

# Test users configuration
declare -A USERS=(
    ["testuser1"]="testpass1"
    ["testuser2"]="testpass2"
    ["testuser3"]="testpass3"
)

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

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v oc &> /dev/null; then
        print_error "oc command not found. Please install the OpenShift CLI."
        exit 1
    fi
    
    if ! oc whoami &> /dev/null; then
        print_error "Not logged in to OpenShift."
        exit 1
    fi
    
    # Check if user has cluster-admin permissions
    if ! oc auth can-i create oauths.config.openshift.io --all-namespaces &> /dev/null; then
        print_warning "You may not have cluster-admin permissions. Some operations may fail."
        print_status "This script requires cluster-admin permissions to configure identity providers."
    fi
    
    # Check if htpasswd command is available
    if ! command -v htpasswd &> /dev/null; then
        print_error "htpasswd command not found. Please install apache2-utils (Debian/Ubuntu) or httpd-tools (RHEL/CentOS/Fedora)."
        print_status "On Fedora/RHEL: sudo dnf install httpd-tools"
        print_status "On Ubuntu/Debian: sudo apt-get install apache2-utils"
        exit 1
    fi

    # jq or python3: required to build the same JSON merge patch used for real updates and server-side dry-run
    if ! command -v jq &> /dev/null && ! command -v python3 &> /dev/null; then
        print_error "jq or python3 is required to build OAuth merge patches."
        print_status "On Fedora/RHEL: sudo dnf install jq   (or: python3)"
        print_status "On Ubuntu/Debian: sudo apt-get install jq"
        exit 1
    fi
    
    print_status "Prerequisites check passed."
}

# Write /tmp/oauth-spec-patch.json: current identityProviders minus $IDENTITY_PROVIDER_NAME, then append htpasswd IdP.
write_oauth_htpasswd_merge_patch_json() {
    if ! oc get oauth cluster -o json > /tmp/oauth-current.json 2>/dev/null; then
        print_error "Cannot read oauth cluster."
        return 1
    fi
    if command -v jq &> /dev/null; then
        jq --arg name "$IDENTITY_PROVIDER_NAME" --arg secret "$SECRET_NAME" '
            ((.spec // {}).identityProviders // []) as $all |
            ($all | map(select(.name != $name))) as $filtered |
            ($filtered + [{
                name: $name,
                type: "HTPasswd",
                htpasswd: { fileData: { name: $secret } },
                mappingMethod: "claim"
            }]) as $out |
            { spec: { identityProviders: $out } }
        ' /tmp/oauth-current.json > /tmp/oauth-spec-patch.json
        return 0
    fi
    if command -v python3 &> /dev/null; then
        IDENTITY_PROVIDER_NAME="$IDENTITY_PROVIDER_NAME" SECRET_NAME="$SECRET_NAME" python3 <<'PY'
import json
import os

ident = os.environ["IDENTITY_PROVIDER_NAME"]
secret = os.environ["SECRET_NAME"]
with open("/tmp/oauth-current.json", "r", encoding="utf-8") as f:
    oauth = json.load(f)
spec = oauth.setdefault("spec", {})
idps = [p for p in (spec.get("identityProviders") or []) if p.get("name") != ident]
idps.append({
    "name": ident,
    "type": "HTPasswd",
    "htpasswd": {"fileData": {"name": secret}},
    "mappingMethod": "claim",
})
with open("/tmp/oauth-spec-patch.json", "w", encoding="utf-8") as f:
    json.dump({"spec": {"identityProviders": idps}}, f)
PY
        return 0
    fi
    print_error "jq or python3 is required."
    return 1
}

# After oauth/cluster IdP setup fails (e.g. HCP), point at MCP deploy (OAuthClient CR is separate from oauth/cluster).
print_mcp_gateway_deploy_hint() {
    local here
    here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
    print_status "MCP Gateway + Shield use an OAuthClient (oauth.openshift.io), not oauth/cluster IdPs."
    print_status "The deploy script registers redirect URIs for YOUR Route host; do not reuse another cluster OAuthClient unless its redirectURIs match exactly."
    print_status "Deploy from examples (default client id mcp-gateway; override only if an admin pre-created a matching OAuthClient):"
    print_status "  cd \"$here\" && ./deploy-openshift-mcp-gateway-sidecar.sh"
    print_status "  cd \"$here\" && ./deploy-openshift-mcp-gateway-sidecar.sh --client-id YOUR_NAME   # only if redirectURIs include https://<same-service>.apps.<cluster>/oauth/callback"
    print_status ""
}

# Same merge patch as configure_oauth, with oc patch --dry-run=server (empty merge {} often skips admission; real spec does not).
check_oauth_htpasswd_merge_patch_dry_run() {
    print_status "Server-side dry-run: oauth/cluster must accept the htpasswd IdP merge patch..."
    if ! oc get oauth cluster &>/dev/null; then
        print_error "Cannot read oauth cluster resource."
        return 1
    fi
    if ! write_oauth_htpasswd_merge_patch_json; then
        return 1
    fi
    local err rc
    err=$(oc patch oauth cluster --type=merge --patch-file=/tmp/oauth-spec-patch.json --dry-run=server 2>&1)
    rc=$?
    if [ "$rc" -eq 0 ]; then
        print_status "Dry-run succeeded; this cluster allows this OAuth update."
        return 0
    fi
    print_error "OAuth merge patch was rejected (ROSA HCP / HyperShift ValidatingAdmissionPolicy, validation, etc.)."
    print_status "This script cannot add an htpasswd identity provider here if the control plane blocks oauth/cluster updates."
    print_status ""
    print_status "What to do instead:"
    print_status "  - Use identities from an IdP already configured on the cluster for MCP OAuth."
    print_status "  - On hosted offerings, configure IdPs via your platform (OCM / HostedCluster / administrator), not oc patch oauth."
    print_status "  - For unrestricted oauth/cluster edits, use a self-managed cluster (IPI, CRC, etc.)."
    print_status ""
    print_status "Server response (truncated):"
    echo "$err" | head -c 1200 | sed 's/^/  /'
    print_status ""
    print_mcp_gateway_deploy_hint
    return 1
}

# Create htpasswd file
create_htpasswd_file() {
    print_step "Creating htpasswd file..."
    
    # Remove existing file if it exists
    rm -f "$HTPASSWD_FILE"
    
    # Create htpasswd file with test users
    # Use a temporary file to ensure we don't lose data
    TEMP_HTPASSWD="/tmp/htpasswd-temp"
    rm -f "$TEMP_HTPASSWD"
    
    FIRST_USER=true
    for username in "${!USERS[@]}"; do
        password="${USERS[$username]}"
        print_status "Adding user: $username"
        
        if [ "$FIRST_USER" = true ]; then
            # First user: create file with -c flag
            if ! htpasswd -b -c "$TEMP_HTPASSWD" "$username" "$password" 2>&1; then
                print_error "Failed to create htpasswd file with user $username"
                return 1
            fi
            FIRST_USER=false
        else
            # Subsequent users: append without -c flag
            if ! htpasswd -b "$TEMP_HTPASSWD" "$username" "$password" 2>&1; then
                print_error "Failed to add user $username to htpasswd file"
                return 1
            fi
        fi
        
        # Verify user was added
        if ! grep -q "^${username}:" "$TEMP_HTPASSWD" 2>/dev/null; then
            print_error "User $username was not found in htpasswd file after adding"
            return 1
        fi
    done
    
    # Move temp file to final location
    mv "$TEMP_HTPASSWD" "$HTPASSWD_FILE"
    
    # Verify the file was created and has content
    if [ ! -f "$HTPASSWD_FILE" ] || [ ! -s "$HTPASSWD_FILE" ]; then
        print_error "htpasswd file was not created or is empty"
        return 1
    fi
    
    # Verify all users are in the file
    USER_COUNT=$(wc -l < "$HTPASSWD_FILE")
    EXPECTED_COUNT=${#USERS[@]}
    
    if [ "$USER_COUNT" -ne "$EXPECTED_COUNT" ]; then
        print_error "Expected $EXPECTED_COUNT users in htpasswd file, but found $USER_COUNT"
        print_status "File contents:"
        cat "$HTPASSWD_FILE"
        return 1
    fi
    
    print_status "htpasswd file created successfully at $HTPASSWD_FILE"
    print_status "Verifying htpasswd file contents..."
    print_status "$USER_COUNT users in htpasswd file:"
    for username in "${!USERS[@]}"; do
        if grep -q "^${username}:" "$HTPASSWD_FILE" 2>/dev/null; then
            print_status "  ✓ $username"
        else
            print_error "  ✗ $username (missing!)"
            return 1
        fi
    done
}

# Create or update Secret
create_secret() {
    print_step "Creating/updating Secret..."
    
    # Verify htpasswd file exists and has content
    if [ ! -f "$HTPASSWD_FILE" ] || [ ! -s "$HTPASSWD_FILE" ]; then
        print_error "htpasswd file does not exist or is empty. Cannot create secret."
        return 1
    fi
    
    # Check if secret already exists
    if oc get secret "$SECRET_NAME" -n "$NAMESPACE" &>/dev/null; then
        print_warning "Secret '$SECRET_NAME' already exists. Updating..."
        oc delete secret "$SECRET_NAME" -n "$NAMESPACE" --ignore-not-found=true
    fi
    
    # Create secret from htpasswd file
    oc create secret generic "$SECRET_NAME" \
        --from-file=htpasswd="$HTPASSWD_FILE" \
        -n "$NAMESPACE"
    
    if [ $? -ne 0 ]; then
        print_error "Failed to create secret '$SECRET_NAME'"
        return 1
    fi
    
    # Verify the secret was created and has the htpasswd key
    if ! oc get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.data.htpasswd}' &>/dev/null; then
        print_error "Secret created but missing htpasswd key"
        return 1
    fi
    
    print_status "Secret '$SECRET_NAME' created successfully in namespace '$NAMESPACE'"
}

# Configure OAuth identity provider
configure_oauth() {
    print_step "Configuring OAuth identity provider..."

    print_status "Reading current OAuth configuration..."
    oc get oauth cluster -o yaml > /tmp/oauth-backup.yaml
    print_status "OAuth configuration backed up to /tmp/oauth-backup.yaml"

    print_status "Building merge patch (replace existing '$IDENTITY_PROVIDER_NAME' entry if present, then add htpasswd IdP)..."
    if ! write_oauth_htpasswd_merge_patch_json; then
        return 1
    fi

    print_status "Applying OAuth configuration..."
    if ! oc patch oauth cluster --type=merge --patch-file=/tmp/oauth-spec-patch.json; then
        print_error "Failed to patch oauth cluster."
        print_status "If the error mentions HostedCluster or ValidatingAdmissionPolicy, this cluster blocks oauth updates from this API."
        return 1
    fi
    
    print_status "OAuth identity provider configured successfully."
    print_warning "It may take a few minutes for the OAuth server to restart and pick up the changes."
    
    # Verify the identity provider was added
    print_status "Verifying identity provider configuration..."
    if oc get oauth cluster -o jsonpath='{.spec.identityProviders[*].name}' 2>/dev/null | grep -q "$IDENTITY_PROVIDER_NAME"; then
        print_status "Identity provider '$IDENTITY_PROVIDER_NAME' is configured."
    else
        print_warning "Identity provider '$IDENTITY_PROVIDER_NAME' not found in OAuth configuration."
        print_status "This may be normal if the OAuth server hasn't restarted yet."
    fi
}

# Merge patch JSON: drop identity provider named $IDENTITY_PROVIDER_NAME only.
write_oauth_remove_identity_merge_patch_json() {
    if ! oc get oauth cluster -o json > /tmp/oauth-current.json 2>/dev/null; then
        print_error "Cannot read oauth cluster."
        return 1
    fi
    if command -v jq &> /dev/null; then
        jq --arg n "$IDENTITY_PROVIDER_NAME" '
            .spec //= {} |
            .spec.identityProviders //= [] |
            { spec: { identityProviders: [.spec.identityProviders[] | select(.name != $n)] } }
        ' /tmp/oauth-current.json > /tmp/oauth-spec-patch.json
        return 0
    fi
    if command -v python3 &> /dev/null; then
        IDENTITY_PROVIDER_NAME="$IDENTITY_PROVIDER_NAME" python3 <<'PY'
import json
import os

ident = os.environ["IDENTITY_PROVIDER_NAME"]
with open("/tmp/oauth-current.json", "r", encoding="utf-8") as f:
    oauth = json.load(f)
spec = oauth.get("spec") or {}
idps = [p for p in (spec.get("identityProviders") or []) if p.get("name") != ident]
with open("/tmp/oauth-spec-patch.json", "w", encoding="utf-8") as f:
    json.dump({"spec": {"identityProviders": idps}}, f)
PY
        return 0
    fi
    print_error "jq or python3 is required."
    return 1
}

# Remove identity provider
remove_identity_provider() {
    print_status "Removing identity provider '$IDENTITY_PROVIDER_NAME'..."

    CURRENT_PROVIDERS=$(oc get oauth cluster -o jsonpath='{.spec.identityProviders[*].name}' 2>/dev/null || echo "")
    if ! echo "$CURRENT_PROVIDERS" | grep -q "$IDENTITY_PROVIDER_NAME"; then
        print_status "Identity provider '$IDENTITY_PROVIDER_NAME' not found."
        return 0
    fi

    if ! write_oauth_remove_identity_merge_patch_json; then
        return 1
    fi

    local dry_out rc
    dry_out=$(oc patch oauth cluster --type=merge --patch-file=/tmp/oauth-spec-patch.json --dry-run=server 2>&1)
    rc=$?
    if [ "$rc" -ne 0 ]; then
        print_warning "Skipping OAuth identity provider removal (server rejected dry-run):"
        echo "$dry_out" | head -c 800 | sed 's/^/  /'
        return 0
    fi

    if ! oc patch oauth cluster --type=merge --patch-file=/tmp/oauth-spec-patch.json; then
        print_error "Failed to remove identity provider from oauth cluster."
        return 1
    fi

    print_status "Identity provider removed."
}

# Wait for OAuth server to be ready
wait_for_oauth() {
    print_step "Waiting for OAuth server to be ready..."
    
    print_status "This may take 1-2 minutes..."
    timeout=120
    elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        if oc get deployment oauth-openshift -n openshift-authentication -o jsonpath='{.status.readyReplicas}' 2>/dev/null | grep -q "2"; then
            print_status "OAuth server is ready!"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
        printf "."
    done
    
    print_warning "OAuth server may still be restarting. Users should be available shortly."
}

# Grant roles to test users
grant_user_roles() {
    print_step "Granting roles to test users..."
    
    # Wait a bit for users to be available after OAuth server restart
    print_status "Waiting for users to be available..."
    sleep 10
    
    for username in "${!USERS[@]}"; do
        print_status "Granting roles to user: $username"
        
        # Grant basic-user role to all users (required for login)
        # Delete existing binding first to ensure clean update
        oc delete clusterrolebinding "test-${username}-basic-user" --ignore-not-found=true 2>/dev/null
        oc create clusterrolebinding "test-${username}-basic-user" \
            --clusterrole=basic-user \
            --user="$username" 2>/dev/null || \
        print_warning "Failed to grant basic-user to $username (may need to wait for user to be available)"
        
        # Customize roles based on username
        case "$username" in
            testuser1)
                # testuser1: Full access (cluster-reader + self-provisioner)
                print_status "  Granting full access to $username"
                
                # Remove any existing bindings for other roles first
                oc delete clusterrolebinding "test-${username}-cluster-reader" --ignore-not-found=true 2>/dev/null
                oc delete clusterrolebinding "test-${username}-self-provisioner" --ignore-not-found=true 2>/dev/null
                oc delete rolebinding "test-${username}-view" -n default --ignore-not-found=true 2>/dev/null
                
                # Create new bindings
                oc create clusterrolebinding "test-${username}-cluster-reader" \
                    --clusterrole=cluster-reader \
                    --user="$username" 2>/dev/null || \
                print_warning "Failed to grant cluster-reader to $username"
                
                oc create clusterrolebinding "test-${username}-self-provisioner" \
                    --clusterrole=self-provisioner \
                    --user="$username" 2>/dev/null || \
                print_warning "Failed to grant self-provisioner to $username"
                ;;
            testuser2)
                # testuser2: Only access to default namespace
                print_status "  Granting access to default namespace only for $username"
                
                # Remove any existing cluster-wide bindings
                oc delete clusterrolebinding "test-${username}-cluster-reader" --ignore-not-found=true 2>/dev/null
                oc delete clusterrolebinding "test-${username}-self-provisioner" --ignore-not-found=true 2>/dev/null
                
                # Ensure default namespace exists
                oc get namespace default &>/dev/null || oc create namespace default
                
                # Grant view role in default namespace
                oc delete rolebinding "test-${username}-view" -n default --ignore-not-found=true 2>/dev/null
                oc create rolebinding "test-${username}-view" \
                    --clusterrole=view \
                    --user="$username" \
                    -n default 2>/dev/null || \
                print_warning "Failed to grant view role to $username in default namespace"
                ;;
            testuser3)
                # testuser3: Only login, no project access
                print_status "  Granting login-only access to $username (no project access)"
                
                # Remove any existing bindings
                oc delete clusterrolebinding "test-${username}-cluster-reader" --ignore-not-found=true 2>/dev/null
                oc delete clusterrolebinding "test-${username}-self-provisioner" --ignore-not-found=true 2>/dev/null
                oc delete rolebinding "test-${username}-view" -n default --ignore-not-found=true 2>/dev/null
                
                # Only basic-user role is granted above, no additional roles
                ;;
            *)
                # Default: grant cluster-reader for any other users
                print_status "  Granting default access to $username"
                oc delete clusterrolebinding "test-${username}-cluster-reader" --ignore-not-found=true 2>/dev/null
                oc create clusterrolebinding "test-${username}-cluster-reader" \
                    --clusterrole=cluster-reader \
                    --user="$username" 2>/dev/null || \
                print_warning "Failed to grant cluster-reader to $username"
                ;;
        esac
    done
    
    print_status "Roles granted to test users."
    print_warning "Note: Users may need to log out and log back in for roles to take effect."
}

# Display user information
display_user_info() {
    print_status ""
    print_status "═══════════════════════════════════════════════════════════"
    print_status "Test Users Created:"
    print_status "═══════════════════════════════════════════════════════════"
    
    for username in "${!USERS[@]}"; do
        password="${USERS[$username]}"
        print_status "Username: $username"
        print_status "Password: $password"
        print_status ""
    done
    
    print_status "═══════════════════════════════════════════════════════════"
    print_status ""
    print_status "To test login:"
    print_status "  oc login -u testuser1 -p testpass1"
    print_status ""
    print_status "Or use the web console:"
    print_status "  https://console-openshift-console.apps.<your-cluster-domain>"
    print_status ""
    print_status "Roles granted to test users:"
    print_status "  testuser1:"
    print_status "    - cluster-reader: Read-only cluster access"
    print_status "    - self-provisioner: Can create new projects"
    print_status "    - basic-user: Basic authenticated user permissions"
    print_status "  testuser2:"
    print_status "    - view role in default namespace only"
    print_status "    - basic-user: Basic authenticated user permissions"
    print_status "  testuser3:"
    print_status "    - basic-user: Login only, no project access"
    print_status ""
    print_status "Troubleshooting login issues:"
    print_status "  1. Wait 2-3 minutes after running this script for OAuth server to restart"
    print_status "  2. Verify the secret exists: oc get secret $SECRET_NAME -n $NAMESPACE"
    print_status "  3. Check OAuth pods: oc get pods -n openshift-authentication"
    print_status "  4. View OAuth logs: oc logs -n openshift-authentication -l app=oauth-openshift --tail=50"
    print_status "  5. Verify identity provider: oc get oauth cluster -o yaml | grep -A 10 htpasswd"
    print_status ""
    print_status "Note: Users are created automatically on first successful login."
    print_status "      If login fails, check OAuth server logs for authentication errors."
    print_status ""
}

# Cleanup function
cleanup() {
    print_status "Cleaning up temporary files..."
    rm -f "$HTPASSWD_FILE" /tmp/oauth-backup.yaml /tmp/oauth-current.json /tmp/oauth-updated.json /tmp/oauth-current.yaml /tmp/oauth-updated.yaml /tmp/oauth-patch.yaml /tmp/oauth-spec-patch.yaml /tmp/oauth-spec-patch.json
}

# Cleanup deployment
cleanup_deployment() {
    print_status "Cleaning up test users and htpasswd configuration..."
    
    # Remove identity provider
    remove_identity_provider
    
    # Delete secret
    print_status "Deleting Secret..."
    oc delete secret "$SECRET_NAME" -n "$NAMESPACE" --ignore-not-found=true 2>/dev/null || true
    
    # Remove role bindings
    print_status "Removing role bindings..."
    for username in "${!USERS[@]}"; do
        # Remove cluster role bindings
        oc delete clusterrolebinding "test-${username}-cluster-reader" --ignore-not-found=true 2>/dev/null || true
        oc delete clusterrolebinding "test-${username}-self-provisioner" --ignore-not-found=true 2>/dev/null || true
        oc delete clusterrolebinding "test-${username}-basic-user" --ignore-not-found=true 2>/dev/null || true
        
        # Remove namespace role bindings (for testuser2)
        oc delete rolebinding "test-${username}-view" -n default --ignore-not-found=true 2>/dev/null || true
    done
    
    # Clean up temporary files
    cleanup
    
    print_status ""
    print_status "Cleanup completed successfully!"
    print_status ""
    print_warning "Note: The test users may still exist in OpenShift. To remove them:"
    print_status "  oc delete user testuser1 testuser2 testuser3"
    print_status "  oc delete identity htpasswd:testuser1 htpasswd:testuser2 htpasswd:testuser3"
}

# Main setup function
main() {
    print_status "Setting up OpenShift test users with htpasswd..."
    print_status ""
    
    check_prerequisites
    create_htpasswd_file
    create_secret
    if ! check_oauth_htpasswd_merge_patch_dry_run; then
        exit 1
    fi
    configure_oauth
    wait_for_oauth
    grant_user_roles
    display_user_info
    cleanup
    
    print_status ""
    print_status "Setup completed successfully!"
}

# Update roles for existing users
update_user_roles() {
    print_status "Updating roles for existing test users..."
    print_status ""
    
    check_prerequisites
    grant_user_roles
    display_user_info
    
    print_status ""
    print_status "Roles updated successfully!"
}

# Show usage information
show_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --cleanup                 Clean up test users and htpasswd configuration
  --update-roles            Update roles for existing test users
  --help                    Show this help message

This script creates 3 test users in OpenShift using htpasswd authentication:
  - testuser1 / testpass1 (full access)
  - testuser2 / testpass2 (default namespace only)
  - testuser3 / testpass3 (login only, no project access)

Prerequisites:
  - OpenShift CLI (oc) installed and logged in
  - Cluster-admin permissions (or ability to modify OAuth and Secrets)
  - htpasswd command available (apache2-utils or httpd-tools)
  - jq or python3 (to build the OAuth JSON merge patch used for dry-run and apply)

Not supported (script exits after server-side dry-run of the real OAuth merge patch):
  - Clusters where oauth/cluster updates are denied (e.g. ROSA HCP / HyperShift). An empty oc patch is often a no-op
    and bypasses admission; this script dry-runs the same spec.identityProviders merge used for the real apply.

Examples:
  $0                      # Create test users with roles
  $0 --update-roles       # Update roles for existing users
  $0 --cleanup            # Remove test users and configuration
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --cleanup)
            cleanup_deployment
            exit 0
            ;;
        --update-roles)
            update_user_roles
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

