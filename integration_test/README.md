# Integration Test

An SSH server deployment for testing the cloaking device end-to-end.

## Deploy

```bash
# Deploy the SSH server
kubectl apply -f ssh-server.yaml

# Wait for the external IP
kubectl get svc ssh-server -n kcd-integration-test -w
```

## Verify SSH is Reachable (Before Cloaking)

```bash
SSH_IP=$(kubectl get svc ssh-server -n kcd-integration-test \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

ssh-keyscan -p 22 -T 5 "$SSH_IP"
# Should return the SSH banner
```

## Apply the CloakingDevice

```bash
kubectl apply -f cloakingdevice.yaml
```

## Verify SSH is Blocked

```bash
ssh-keyscan -p 22 -T 5 "$SSH_IP"
# Should time out — the service is cloaked
```

## Authorize and Verify Access Restored

```bash
kcd authorize --server "$KCD_IP" \
  --knock-password "$KNOCK_PW" \
  --access-password "$ACCESS_PW" \
  --insecure

ssh-keyscan -p 22 -T 5 "$SSH_IP"
# Should return the SSH banner again
```

## Clean Up

```bash
kubectl delete -f cloakingdevice.yaml
kubectl delete -f ssh-server.yaml
```
