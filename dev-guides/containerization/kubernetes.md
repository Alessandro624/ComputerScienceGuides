# Kubernetes

## Scopo

Questa guida fornisce una panoramica di Kubernetes (K8s), la piattaforma di orchestrazione container per il deployment, scaling e gestione di applicazioni containerizzate.

## Prerequisiti

- Docker installato
- kubectl CLI
- Cluster Kubernetes (minikube, kind, o cloud)
- Conoscenza base di container

## Installazione

### kubectl

```bash
# Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Windows
winget install -e --id Kubernetes.kubectl

# macOS
brew install kubectl
```

### Minikube (Sviluppo Locale)

```bash
# Linux
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# Avvio
minikube start
```

### Kind (Kubernetes in Docker)

```bash
# Installazione
go install sigs.k8s.io/kind@latest

# Crea cluster
kind create cluster --name dev
```

---

## Architettura

```
Cluster Kubernetes
├── Control Plane
│   ├── API Server
│   ├── etcd
│   ├── Scheduler
│   └── Controller Manager
└── Worker Nodes
    ├── kubelet
    ├── kube-proxy
    └── Container Runtime
```

---

## kubectl Comandi Base

### Informazioni Cluster

```bash
# Versione
kubectl version

# Info cluster
kubectl cluster-info

# Nodi
kubectl get nodes
kubectl describe node NODE_NAME
```

### Risorse

```bash
# Lista risorse
kubectl get pods
kubectl get deployments
kubectl get services
kubectl get all

# Tutti i namespace
kubectl get pods --all-namespaces
kubectl get pods -A

# Output dettagliato
kubectl get pods -o wide
kubectl get pods -o yaml
kubectl get pods -o json
```

### Descrizione e Log

```bash
# Dettagli
kubectl describe pod POD_NAME
kubectl describe deployment DEPLOYMENT_NAME

# Log
kubectl logs POD_NAME
kubectl logs POD_NAME -c CONTAINER_NAME
kubectl logs -f POD_NAME  # Follow
kubectl logs --tail=100 POD_NAME
```

### Esecuzione Comandi

```bash
# Shell nel pod
kubectl exec -it POD_NAME -- /bin/bash
kubectl exec -it POD_NAME -c CONTAINER -- sh

# Comando singolo
kubectl exec POD_NAME -- ls /app
```

---

## Pod

### Pod YAML

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  labels:
    app: myapp
spec:
  containers:
  - name: main
    image: nginx:latest
    ports:
    - containerPort: 80
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
```

```bash
# Crea
kubectl apply -f pod.yaml

# Elimina
kubectl delete pod my-pod
kubectl delete -f pod.yaml
```

---

## Deployment

### Deployment YAML

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: app
        image: myapp:v1
        ports:
        - containerPort: 8080
```

### Gestione Deployment

```bash
# Crea/aggiorna
kubectl apply -f deployment.yaml

# Scale
kubectl scale deployment my-deployment --replicas=5

# Rollout
kubectl rollout status deployment/my-deployment
kubectl rollout history deployment/my-deployment
kubectl rollout undo deployment/my-deployment
kubectl rollout restart deployment/my-deployment
```

---

## Service

### ClusterIP (Interno)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  selector:
    app: myapp
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
```

### NodePort (Esterno via Nodo)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-nodeport
spec:
  type: NodePort
  selector:
    app: myapp
  ports:
  - port: 80
    targetPort: 8080
    nodePort: 30080
```

### LoadBalancer (Cloud)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-lb
spec:
  type: LoadBalancer
  selector:
    app: myapp
  ports:
  - port: 80
    targetPort: 8080
```

---

## ConfigMap e Secret

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  DATABASE_HOST: "db.example.com"
  LOG_LEVEL: "info"
```

### Secret

```bash
# Crea secret
kubectl create secret generic db-secret \
  --from-literal=username=admin \
  --from-literal=password=secret123
```

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-secret
type: Opaque
data:
  username: YWRtaW4=  # base64
  password: c2VjcmV0MTIz
```

### Uso in Pod

```yaml
spec:
  containers:
  - name: app
    env:
    - name: DB_HOST
      valueFrom:
        configMapKeyRef:
          name: app-config
          key: DATABASE_HOST
    - name: DB_PASS
      valueFrom:
        secretKeyRef:
          name: db-secret
          key: password
```

---

## Namespace

```bash
# Lista
kubectl get namespaces

# Crea
kubectl create namespace dev

# Usa namespace
kubectl get pods -n dev
kubectl config set-context --current --namespace=dev
```

---

## Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
spec:
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-service
            port:
              number: 80
```

---

## Comandi Utili

```bash
# Port forward
kubectl port-forward pod/POD_NAME 8080:80
kubectl port-forward svc/SERVICE_NAME 8080:80

# Copia file
kubectl cp POD_NAME:/path/file ./local
kubectl cp ./local POD_NAME:/path/

# Watch
kubectl get pods -w

# Dry run
kubectl apply -f file.yaml --dry-run=client
kubectl apply -f file.yaml --dry-run=server
```

---

## Best Practices

- **Namespace**: Separa ambienti con namespace
- **Resources**: Definisci sempre requests/limits
- **Labels**: Usa label consistenti
- **Probes**: Configura liveness/readiness
- **Secrets**: Non hardcodare credenziali

## Riferimenti

- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [kubectl Cheat Sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)
- [Kubernetes Patterns](https://k8spatterns.io/)
