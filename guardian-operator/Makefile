IMG ?= ghcr.io/naveed-gung/zero-day-guardian/guardian-operator:latest
CRD_OPTIONS ?= "crd:generateEmbeddedObjectMeta=true"
ENVTEST_K8S_VERSION = 1.30.0

.PHONY: all
all: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: fmt vet ## Run tests.
	go test ./... -coverprofile cover.out

.PHONY: lint
lint: ## Run golangci-lint.
	golangci-lint run --timeout=5m

##@ Build

.PHONY: build
build: fmt vet ## Build manager binary.
	go build -o bin/manager ./cmd/main.go

.PHONY: run
run: fmt vet ## Run the controller locally (outside the cluster).
	go run ./cmd/main.go

.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	docker build -t $(IMG) .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push $(IMG)

##@ Deployment

.PHONY: install
install: ## Install CRDs into the K8s cluster.
	kubectl apply -f deploy/base/crd/

.PHONY: uninstall
uninstall: ## Uninstall CRDs from the K8s cluster.
	kubectl delete -f deploy/base/crd/

.PHONY: deploy
deploy: ## Deploy controller to the K8s cluster.
	kubectl apply -k deploy/overlays/dev

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster.
	kubectl delete -k deploy/overlays/dev

.PHONY: deploy-prod
deploy-prod: ## Deploy controller to the K8s cluster (production overlay).
	kubectl apply -k deploy/overlays/prod

##@ Generate

.PHONY: generate
generate: ## Generate code (deepcopy, etc.).
	controller-gen object paths="./..."

.PHONY: manifests
manifests: ## Generate CRD manifests.
	controller-gen $(CRD_OPTIONS) rbac:roleName=guardian-operator webhook paths="./..." output:crd:artifacts:config=deploy/base/crd

.PHONY: clean
clean: ## Remove build artifacts.
	rm -rf bin/ cover.out
