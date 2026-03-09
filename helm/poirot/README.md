# Poirot Helm Chart

Deploy Poirot DSPM on Kubernetes using Helm.

## Components

| Component | Image | Description |
|-----------|-------|-------------|
| Dashboard | `ghcr.io/safernandez666/poirot-dashboard:latest` | Flask API + Next.js frontend (nginx) |
| Scanner | `ghcr.io/safernandez666/poirot-scanner:latest` | Hawk scanner (kept alive for ad-hoc `kubectl exec`) |
| Keycloak | `quay.io/keycloak/keycloak:26.1` | IAM / SSO (optional, enabled by default) |

> **Note:** In Kubernetes, the dashboard runs scans via local subprocess (scanner code is bundled in the dashboard image). The `KUBERNETES_SERVICE_HOST` env var is auto-detected. The standalone scanner pod is for manual ad-hoc scans only.

## Minikube Quickstart

```bash
# 1. Start Minikube (4GB RAM recommended for Keycloak)
minikube start --memory=4096 --cpus=2

# 2. Clone the repo (ConfigMaps need repo files)
git clone https://github.com/safernandez666/poirot.git
cd poirot

# 3. Install with the helper script
cd k8s/charts/poirot
chmod +x install.sh
./install.sh

# 4. Wait for pods to be ready (~2-3 min for Keycloak)
kubectl get pods -n poirot -w

# 5. Access the dashboard
minikube service dashboard -n poirot
```

### Manual install (without helper script)

```bash
# Create namespace
kubectl create namespace poirot

# Create ConfigMaps from repo files
kubectl create configmap poirot-fingerprint \
  --from-file=fingerprint.yml=hawk-scanner/fingerprint.yml -n poirot
kubectl create configmap poirot-connection-seed \
  --from-file=connection.yml=hawk-scanner/connection.yml -n poirot
kubectl create configmap poirot-scripts \
  --from-file=notification_manager.py=hawk-scanner/notification_manager.py -n poirot
kubectl create configmap poirot-keycloak-realm \
  --from-file=poirot-realm.json=keycloak/poirot-realm.json -n poirot
kubectl create configmap poirot-keycloak-theme \
  --from-file=login.css=keycloak/themes/poirot/login/resources/css/login.css -n poirot

# Install chart
helm install poirot k8s/charts/poirot -n poirot
```

## Configuration

Override values with `--set` or a custom `values.yaml`:

```bash
# Add a MySQL data source
helm install poirot k8s/charts/poirot -n poirot \
  --set 'dataSources.SOURCE_MYSQL_PROD={"host":"db.example.com","port":3306,"user":"scanner","password":"s3cr3t","database":"prod"}'

# Disable Keycloak
helm install poirot k8s/charts/poirot -n poirot \
  --set keycloak.enabled=false \
  --set auth.enabled=false

# Use Ingress instead of NodePort
helm install poirot k8s/charts/poirot -n poirot \
  --set dashboard.service.type=ClusterIP \
  --set ingress.enabled=true \
  --set ingress.host=poirot.example.com

# Enable OpenRouter AI
helm install poirot k8s/charts/poirot -n poirot \
  --set ai.provider=openrouter \
  --set ai.openrouter.apiKey=sk-or-... \
  --set ai.openrouter.model=google/gemma-2-9b-it:free
```

## Default Users (Keycloak)

| User | Password | Role | Temporary? |
|------|----------|------|------------|
| poirot-admin | admin | admin | yes |
| admin-user | Test1234! | admin | yes |
| analyst-user | Test1234! | analyst | yes |
| viewer-user | Test1234! | viewer | yes |

## Uninstall

```bash
helm uninstall poirot -n poirot
kubectl delete namespace poirot
```

## Key Values

| Parameter | Default | Description |
|-----------|---------|-------------|
| `dashboard.image` | `ghcr.io/safernandez666/poirot-dashboard:latest` | Dashboard image |
| `scanner.image` | `ghcr.io/safernandez666/poirot-scanner:latest` | Scanner image |
| `keycloak.enabled` | `true` | Deploy Keycloak |
| `auth.enabled` | `"true"` | Require authentication |
| `dashboard.service.type` | `NodePort` | Service type |
| `dashboard.service.nodePort` | `30080` | NodePort port |
| `ingress.enabled` | `false` | Enable Ingress |
| `persistence.data.size` | `2Gi` | Data PVC size |
| `ai.provider` | `ollama` | AI provider (ollama/openrouter) |
| `dataSources` | `{}` | Data sources (SOURCE_TYPE_NAME: JSON) |
