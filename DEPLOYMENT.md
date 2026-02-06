# Deployment Guide for Aura-ECDH on AKS

## Prerequisites
- Azure Kubernetes Service (AKS) cluster
- `kubectl` configured
- `docker` installed

## Configuration
The application requires the following environment variables. In the provided `k8s/deployment.yaml`, these are configured to be pulled from Kubernetes Secrets or ConfigMaps, or defined directly (for non-sensitive data).

### Required Environment Variables
| Variable | Description |
|----------|-------------|
| `PORT` | The port the application runs on (default: 3000) |
| `BASE_URL` | Application base URL |
| `REDIS_CONNECTION_STRING` | Connection string for Redis |
| `ECC_PRIVATE_KEY` | PEM string or file path to the ECC Private Key (used for entropy) |
| `RSA_PRIVATE_KEY` | PEM string or file path to the RSA Private Key for decryption/signing |

## Steps to Deploy

### 1. Build and Push Docker Image
```bash
# Build the image
docker build -t your-registry.azurecr.io/aura-ecdh:latest .

# Push to your registry (ACR)
docker push your-registry.azurecr.io/aura-ecdh:latest
```

### 2. Configure Secrets
We recommend using Kubernetes Secrets for sensitive keys. The deployment expects three secrets: `app-secrets`, `app-rsa-key`, and `app-ecc-key`.

```bash
# 1. Create secret for RSA Key (from file)
kubectl create secret generic app-rsa-key \
  --from-file=private-key=./keys/rsa.key

# 2. Create secret for ECC Private Key (from file)
# Assuming your private key is in ./keys/ecc.key
kubectl create secret generic app-ecc-key \
  --from-file=private-key=./keys/ecc.key

# 3. Create secret for Redis Connection
kubectl create secret generic app-secrets \
  --from-literal=redis-connection="redis://user:password@host:6379"
```

### 3. Deployment Strategy
The deployment is configured with a **RollingUpdate** strategy to ensure zero downtime during updates:
- **Max Unavailable**: 0 (Always keep desired number of pods running)
- **Max Surge**: 1 (Create one new pod before terminating old ones)

### 4. Apply Kubernetes Manifests
Update `k8s/deployment.yaml` to reference your image.

```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

## Updating the Deployment
To update the application:

1. Build a new image with a new tag.
2. Update the image tag in `k8s/deployment.yaml`.
3. Apply the changes:
   ```bash
   kubectl apply -f k8s/deployment.yaml
   ```
   Or use `kubectl set image`:
   ```bash
   kubectl set image deployment/aura-ecdh aura-ecdh=your-registry.azurecr.io/aura-ecdh:vn
   ```

## Hot-Reload of Keys
The application supports **hot-reloading** of ECC and RSA keys when they are provided as file paths (e.g., in Kubernetes Secrets).

- **Detection**: Changes are detected using OS events (`fs.watch`).
- **Zero-Downtime**: When a Kubernetes Secret is updated, the application will automatically reload the new key content without requiring a pod restart.
- **Resilience**: If a reload fails (e.g., invalid PEM during update), the application will keep the previous valid key in memory and log the error.
