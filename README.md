# GitHub Webhook Fanout Server

A simple Go server built with Fiber v2 that receives GitHub webhooks and triggers ArgoCD deployments across multiple environments.

## Features

- ✅ GitHub webhook signature verification for security
- ✅ Fanout to multiple ArgoCD instances
- ✅ Support for both token and username/password authentication
- ✅ Health check endpoint
- ✅ Comprehensive logging
- ✅ Environment-based configuration
- ✅ Built with Fiber v2 for high performance

## Quick Start

1. **Install dependencies:**
   ```bash
   go mod tidy
   ```

2. **Configure environment variables:**
   ```bash
   # Create .env file with your configuration
   # See the Configuration section below for required variables
   ```

3. **Run the server:**
   ```bash
   go run main.go
   ```

## Configuration

### Environment Variables

- `PORT`: Server port (default: 8080)
- `GITHUB_SECRET`: GitHub webhook secret for signature verification
- `ARGOCD_CONFIGS`: JSON array of ArgoCD configurations

### ArgoCD Configuration Format

```json
[
  {
    "name": "production",
    "url": "https://argocd-prod.example.com",
    "username": "admin",
    "password": "prod-argocd-password-123",
    "appName": "my-app"
  },
  {
    "name": "staging", 
    "url": "https://argocd-staging.example.com",
    "username": "admin",
    "password": "staging-argocd-password-456",
    "appName": "my-app-staging"
  },
  {
    "name": "development",
    "url": "https://argocd-dev.example.com",
    "username": "dev-admin",
    "password": "dev-argocd-password-789",
    "appName": "my-app-dev"
  }
]
```

## API Endpoints

### POST /webhook
Receives GitHub webhooks and triggers ArgoCD syncs.

**Headers:**
- `X-Hub-Signature-256`: GitHub webhook signature (if GITHUB_SECRET is configured)

**Response:**
```json
{
  "message": "Webhook processed successfully",
  "results": [
    {
      "name": "production",
      "url": "https://argocd-prod.example.com",
      "success": true,
      "error": null
    }
  ]
}
```

### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy"
}
```

## GitHub Webhook Setup

1. Go to your GitHub repository settings
2. Navigate to "Webhooks" → "Add webhook"
3. Set the payload URL to: `https://your-server.com/webhook`
4. Set content type to: `application/json`
5. Select events: "Just the push event"
6. Set a secret and configure it in your environment variables
7. Click "Add webhook"

## ArgoCD Authentication

The server supports two authentication methods, with basic authentication being the preferred method:

### Basic Authentication (Recommended)
```json
{
  "name": "prod",
  "url": "https://argocd.example.com",
  "username": "admin",
  "password": "your-argocd-password",
  "appName": "my-app"
}
```

### Token Authentication (Fallback)
```json
{
  "name": "prod",
  "url": "https://argocd.example.com",
  "token": "your-argocd-token",
  "appName": "my-app"
}
```

**Note**: If both username/password and token are provided, basic authentication takes precedence.

## Deployment

### Docker

#### Quick Start
```bash
# Build and run manually
docker build -t github-webhook-fanout .
docker run -p 8080:8080 --env-file .env github-webhook-fanout
```

#### Production Build
```bash
# Build optimized production image
docker build -t github-webhook-fanout:prod .
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: github-webhook-fanout
spec:
  replicas: 2
  selector:
    matchLabels:
      app: github-webhook-fanout
  template:
    metadata:
      labels:
        app: github-webhook-fanout
    spec:
      containers:
      - name: webhook-fanout
        image: your-registry/github-webhook-fanout:latest
        ports:
        - containerPort: 8080
        env:
        - name: PORT
          value: "8080"
        - name: GITHUB_SECRET
          valueFrom:
            secretKeyRef:
              name: webhook-secrets
              key: github-secret
        - name: ARGOCD_CONFIGS
          valueFrom:
            secretKeyRef:
              name: webhook-secrets
              key: argocd-configs
```

## Security Considerations

- Always use HTTPS in production
- Configure GitHub webhook secrets for signature verification
- Use ArgoCD tokens instead of username/password when possible
- Consider using Kubernetes secrets for sensitive configuration
- Implement proper network policies and RBAC

## Troubleshooting

### Common Issues

1. **ArgoCD sync fails**: Check ArgoCD authentication and app permissions
2. **GitHub signature verification fails**: Verify GITHUB_SECRET matches webhook configuration
3. **Server won't start**: Check port availability and configuration format
4. **403 Permission Denied**: Check ArgoCD RBAC settings and user permissions

### Enhanced Debugging

The server provides comprehensive logging for debugging:
- **Webhook reception and processing**
- **ArgoCD session token acquisition**
- **Application existence checks**
- **ArgoCD API calls and responses**
- **Permission-specific error messages**
- **Request/response details**

### Permission Issues

If you encounter 403 "permission denied" errors:

1. **Check ArgoCD RBAC Configuration:**
   ```bash
   kubectl get configmap argocd-rbac-cm -n argocd -o yaml
   ```

2. **Grant Sync Permissions:**
   ```yaml
   data:
     policy.csv: |
       p, role:admin, applications, sync, */*, allow
       p, role:admin, applications, action/*, */*, allow
       g, admin, role:admin
   ```

3. **Verify Application Access:**
   The server now checks application existence before attempting sync operations.

## License

MIT
