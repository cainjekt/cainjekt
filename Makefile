CLUSTER_NAME ?= cainjekt-test-cluster
DEMO_CLUSTER_NAME ?= cainjekt-demo
DEMO_NAMESPACE ?= cainjekt-demo
DEMO_CA_DIR ?= /tmp/cainjekt-demo

.PHONY: build
build:
	mkdir -p bin
	go build -o bin/cainjekt ./cmd/cainjekt

.PHONY: prepare-test-cluster
prepare-test-cluster:
	# Create a kind cluster for testing if it doesn't already exist
	-kind get clusters | grep -q $(CLUSTER_NAME) || kind create cluster --name $(CLUSTER_NAME) --config ./hack/kind.yaml
	kind export kubeconfig --name $(CLUSTER_NAME)

.PHONY: reset-test-cluster
reset-test-cluster:
	-kind delete cluster --name $(CLUSTER_NAME)
	kind create cluster --name $(CLUSTER_NAME) --config ./hack/kind.yaml
	kind export kubeconfig --name $(CLUSTER_NAME)

.PHONY: copy-plugin
copy-plugin: build prepare-test-cluster
	docker cp ./bin/cainjekt $(shell kind get nodes --name=$(CLUSTER_NAME) | head -n 1):/cainjekt

.PHONY: exec-plugin
exec-plugin: copy-plugin
	docker exec -it $(shell kind get nodes --name=$(CLUSTER_NAME) | head -n 1) /cainjekt --idx 10

.PHONY: integration-test
integration-test:
	GOCACHE=/tmp/go-build-cache go test -tags=integration -count=1 -v ./integration

.PHONY: demo
demo: demo-prepare demo-start-plugin demo-apply demo-verify

.PHONY: demo-prepare
demo-prepare: build
	-kind get clusters | grep -q $(DEMO_CLUSTER_NAME) || kind create cluster --name $(DEMO_CLUSTER_NAME) --config ./demo/kind.yaml
	kind export kubeconfig --name $(DEMO_CLUSTER_NAME)
	mkdir -p $(DEMO_CA_DIR)
	openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 7 \
		-subj "/CN=cainjekt-demo-root" \
		-keyout $(DEMO_CA_DIR)/demo-ca.key \
		-out $(DEMO_CA_DIR)/demo-ca.pem >/dev/null 2>&1
	printf "subjectAltName=DNS:private-https.$(DEMO_NAMESPACE).svc.cluster.local,DNS:private-https.$(DEMO_NAMESPACE).svc,DNS:private-https\n" > $(DEMO_CA_DIR)/server.ext
	openssl req -newkey rsa:2048 -sha256 -nodes \
		-subj "/CN=private-https.$(DEMO_NAMESPACE).svc.cluster.local" \
		-keyout $(DEMO_CA_DIR)/server.key \
		-out $(DEMO_CA_DIR)/server.csr >/dev/null 2>&1
	openssl x509 -req -sha256 -days 7 \
		-in $(DEMO_CA_DIR)/server.csr \
		-CA $(DEMO_CA_DIR)/demo-ca.pem \
		-CAkey $(DEMO_CA_DIR)/demo-ca.key \
		-CAcreateserial \
		-out $(DEMO_CA_DIR)/server.crt \
		-extfile $(DEMO_CA_DIR)/server.ext >/dev/null 2>&1
	NODE=$$(kind get nodes --name=$(DEMO_CLUSTER_NAME) | head -n 1); \
	docker cp ./bin/cainjekt $$NODE:/cainjekt; \
	docker exec $$NODE mkdir -p /etc/cainjekt; \
	docker cp $(DEMO_CA_DIR)/demo-ca.pem $$NODE:/etc/cainjekt/ca-bundle.pem

.PHONY: demo-start-plugin
demo-start-plugin:
	NODE=$$(kind get nodes --name=$(DEMO_CLUSTER_NAME) | head -n 1); \
	docker exec $$NODE sh -lc "pkill -f '/cainjekt --idx 10' || true"; \
	docker exec -d $$NODE /cainjekt --idx 10

.PHONY: demo-apply
demo-apply:
	kubectl apply -f ./demo/manifests/00-namespace.yaml
	kubectl -n $(DEMO_NAMESPACE) create secret tls private-https-tls --cert=$(DEMO_CA_DIR)/server.crt --key=$(DEMO_CA_DIR)/server.key --dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -f ./demo/manifests/10-pod-enabled.yaml
	kubectl apply -f ./demo/manifests/20-pod-disabled.yaml
	kubectl apply -f ./demo/manifests/30-pod-mode-off.yaml
	kubectl wait -n $(DEMO_NAMESPACE) --for=condition=Ready pod/private-https-server --timeout=120s
	kubectl wait -n $(DEMO_NAMESPACE) --for=condition=Ready pod/wget-enabled --timeout=120s
	kubectl wait -n $(DEMO_NAMESPACE) --for=condition=Ready pod/wget-disabled --timeout=120s

.PHONY: demo-verify
demo-verify:
	kubectl exec -n $(DEMO_NAMESPACE) wget-enabled -- sh -lc 'wget -qO- --timeout=10 https://private-https.$(DEMO_NAMESPACE).svc.cluster.local:8443/healthz'
	kubectl exec -n $(DEMO_NAMESPACE) wget-disabled -- sh -lc 'if wget -qO- --timeout=10 https://private-https.$(DEMO_NAMESPACE).svc.cluster.local:8443/healthz; then echo "unexpected success"; exit 1; else echo "expected failure (untrusted private CA)"; fi'

.PHONY: demo-clean
demo-clean:
	-kind delete cluster --name $(DEMO_CLUSTER_NAME)
