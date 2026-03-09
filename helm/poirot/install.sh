#!/usr/bin/env bash
# ── Poirot Helm Install Helper ───────────────────────────────────────────────
# Populates ConfigMaps from repo files and runs helm install.
# Usage: cd k8s/charts/poirot && ./install.sh [RELEASE_NAME] [EXTRA_HELM_ARGS...]
#
# Prerequisites: helm, kubectl, a running Kubernetes cluster (minikube, kind, etc.)
set -euo pipefail

RELEASE="${1:-poirot}"
shift 2>/dev/null || true
NAMESPACE="poirot"
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

echo "==> Poirot Helm Installer"
echo "    Release:   $RELEASE"
echo "    Namespace: $NAMESPACE"
echo "    Repo root: $REPO_ROOT"
echo ""

# ── 1. Create namespace ─────────────────────────────────────────────────────
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# ── 2. Populate ConfigMaps from repo source files ────────────────────────────
echo "==> Creating ConfigMaps from repo files..."

kubectl create configmap poirot-fingerprint \
  --from-file=fingerprint.yml="$REPO_ROOT/hawk-scanner/fingerprint.yml" \
  -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap poirot-connection-seed \
  --from-file=connection.yml="$REPO_ROOT/hawk-scanner/connection.yml" \
  -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap poirot-scripts \
  --from-file=notification_manager.py="$REPO_ROOT/hawk-scanner/notification_manager.py" \
  -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

if [ -f "$REPO_ROOT/keycloak/poirot-realm.json" ]; then
  kubectl create configmap poirot-keycloak-realm \
    --from-file=poirot-realm.json="$REPO_ROOT/keycloak/poirot-realm.json" \
    -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
fi

if [ -f "$REPO_ROOT/keycloak/themes/poirot/login/resources/css/login.css" ]; then
  kubectl create configmap poirot-keycloak-theme \
    --from-file=login.css="$REPO_ROOT/keycloak/themes/poirot/login/resources/css/login.css" \
    -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
fi

echo ""

# ── 3. Helm install / upgrade ───────────────────────────────────────────────
echo "==> Running helm upgrade --install..."
helm upgrade --install "$RELEASE" "$(dirname "$0")" \
  --namespace "$NAMESPACE" \
  --create-namespace \
  "$@"

echo ""
echo "==> Done! Run 'helm status $RELEASE -n $NAMESPACE' to check."
