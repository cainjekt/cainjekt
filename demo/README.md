# Cainjekt Demo

このディレクトリは `kind` 上で cainjekt の動作を確認するための最小デモです。

## 1. クラスタ作成

```bash
kind create cluster --name cainjekt-demo --config ./demo/kind.yaml
kind export kubeconfig --name cainjekt-demo
```

## 2. プラグインをビルドして kind node に配置

```bash
make build
NODE=$(kind get nodes --name=cainjekt-demo | head -n 1)
docker cp ./bin/cainjekt ${NODE}:/cainjekt
```

## 3. デモ用CAとサーバー証明書を生成

`cainjekt` は node 内の `/etc/cainjekt/ca-bundle.pem` を参照します。

```bash
mkdir -p /tmp/cainjekt-demo
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 7 \
  -subj "/CN=cainjekt-demo-root" \
  -keyout /tmp/cainjekt-demo/demo-ca.key \
  -out /tmp/cainjekt-demo/demo-ca.pem

cat > /tmp/cainjekt-demo/server.ext <<'EOF'
subjectAltName=DNS:private-https.cainjekt-demo.svc.cluster.local,DNS:private-https.cainjekt-demo.svc,DNS:private-https
EOF

openssl req -newkey rsa:2048 -sha256 -nodes \
  -subj "/CN=private-https.cainjekt-demo.svc.cluster.local" \
  -keyout /tmp/cainjekt-demo/server.key \
  -out /tmp/cainjekt-demo/server.csr

openssl x509 -req -sha256 -days 7 \
  -in /tmp/cainjekt-demo/server.csr \
  -CA /tmp/cainjekt-demo/demo-ca.pem \
  -CAkey /tmp/cainjekt-demo/demo-ca.key \
  -CAcreateserial \
  -out /tmp/cainjekt-demo/server.crt \
  -extfile /tmp/cainjekt-demo/server.ext

docker exec ${NODE} mkdir -p /etc/cainjekt
docker cp /tmp/cainjekt-demo/demo-ca.pem ${NODE}:/etc/cainjekt/ca-bundle.pem
```

## 4. NRI プラグイン起動

```bash
docker exec -d ${NODE} /cainjekt --idx 10
```

## 5. デモマニフェスト適用

```bash
kubectl apply -f ./demo/manifests/00-namespace.yaml
kubectl -n cainjekt-demo create secret tls private-https-tls \
  --cert=/tmp/cainjekt-demo/server.crt \
  --key=/tmp/cainjekt-demo/server.key \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f ./demo/manifests/10-pod-enabled.yaml
kubectl apply -f ./demo/manifests/20-pod-disabled.yaml
kubectl apply -f ./demo/manifests/30-pod-mode-off.yaml
kubectl wait -n cainjekt-demo --for=condition=Ready pod/private-https-server --timeout=120s
kubectl wait -n cainjekt-demo --for=condition=Ready pod/wget-enabled --timeout=120s
kubectl wait -n cainjekt-demo --for=condition=Ready pod/wget-disabled --timeout=120s
```

## 6. 結果確認

`wget-enabled` は private CA を信頼できるため HTTPS で `ok` が返り、`wget-disabled` は失敗します。

```bash
kubectl exec -n cainjekt-demo wget-enabled -- sh -lc \
  'wget -qO- --timeout=10 https://private-https.cainjekt-demo.svc.cluster.local:8443/healthz'

kubectl exec -n cainjekt-demo wget-disabled -- sh -lc \
  'wget -qO- --timeout=10 https://private-https.cainjekt-demo.svc.cluster.local:8443/healthz || echo "expected failure"'
```

## 7. 後片付け

```bash
kind delete cluster --name cainjekt-demo
```
