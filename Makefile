# Modified by the balex42 fork: local WAPI tests and fork image defaults.
# cspell:ignore KUBEBUILDER
GO ?= $(shell which go)
OS ?= $(shell $(GO) env GOOS)
ARCH ?= $(shell $(GO) env GOARCH)

IMAGE_NAME := ghcr.io/balex42/cert-manager-webhook-infoblox-wapi
# IMAGE_TAG is derived from Chart.yaml appVersion if not set
IMAGE_TAG ?= $(shell grep '^appVersion:' charts/cert-manager-webhook-infoblox-wapi/Chart.yaml | cut -d' ' -f2)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD | sed 's/[\/_]/-/g')

OUT := $(shell pwd)/_out

# K8s version for envtest (can be overridden, e.g., make test ENVTEST_K8S_VERSION=1.31.x)
ENVTEST_K8S_VERSION ?= 1.31.x

HELM_FILES := $(shell find charts/cert-manager-webhook-infoblox-wapi)

# Install setup-envtest tool
SETUP_ENVTEST = $(shell pwd)/bin/setup-envtest

.PHONY: help
help: ## Display this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: setup-envtest
setup-envtest: $(SETUP_ENVTEST) ## Install setup-envtest tool for running tests
$(SETUP_ENVTEST): | bin
	GOBIN=$(shell pwd)/bin $(GO) install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

.PHONY: test
test: ## Run unit and local HTTPS WAPI tests (no cluster required)
	$(GO) test -mod=readonly -v ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	$(GO) test -mod=readonly -coverprofile=coverage.out -covermode=atomic ./...

.PHONY: test-race
test-race: ## Run tests with race detector
	$(GO) test -mod=readonly -race ./...

.PHONY: test-integration
test-integration: setup-envtest ## Run conformance tests against a configured live Infoblox environment
	@KUBEBUILDER_ASSETS_PATH="$(shell $(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" && \
	TEST_ASSET_ETCD="$$KUBEBUILDER_ASSETS_PATH/etcd" \
	TEST_ASSET_KUBE_APISERVER="$$KUBEBUILDER_ASSETS_PATH/kube-apiserver" \
	TEST_ASSET_KUBECTL="$$KUBEBUILDER_ASSETS_PATH/kubectl" \
	$(GO) test -mod=readonly -tags=integration -run TestRunsSuite -v .

.PHONY: clean
clean: ## Clean build artifacts and test files
	rm -rf _test $(OUT) bin coverage.out

.PHONY: build
build: ## Build the webhook binary
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -o webhook -ldflags '-s -w' .

.PHONY: build-container
build-container: ## Build the Docker container image
	docker build -t "$(IMAGE_NAME):$(IMAGE_TAG)-$(GIT_BRANCH)" .

.PHONY: push-container
push-container: ## Push the Docker container image to registry
	docker push "$(IMAGE_NAME):$(IMAGE_TAG)-$(GIT_BRANCH)"

.PHONY: helm
helm: $(OUT)/rendered-manifest.yaml ## Render Helm chart templates

$(OUT)/rendered-manifest.yaml: $(HELM_FILES) | $(OUT)
	helm template \
		cert-manager-webhook-infoblox-wapi \
		--set image.repository=$(IMAGE_NAME) \
		--set image.tag=$(IMAGE_TAG) \
		--set infoblox.host=$(INFOBLOX_HOST) \
		charts/cert-manager-webhook-infoblox-wapi > $@

_test $(OUT) bin:
	mkdir -p $@
