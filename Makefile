# Registry configurations
DOCKER_REGISTRY ?= docker.io
GHCR_REGISTRY ?= ghcr.io
ALI_REGISTRY ?= registry.cn-hangzhou.aliyuncs.com

IMAGE ?= ghcr.io/amoylab/unla/allinone:latest
APISERVER_IMAGE ?= ghcr.io/amoylab/unla/apiserver:latest
MCP_GATEWAY_IMAGE ?= ghcr.io/amoylab/unla/mcp-gateway:latest
MOCK_USER_SVC_IMAGE ?= ghcr.io/amoylab/unla/mock-server:latest
WEB_IMAGE ?= ghcr.io/amoylab/unla/web:latest

# Project configurations
PROJECT_NAME ?= unla
IMAGE_TAG ?= $(shell cat pkg/version/VERSION)

# Service configurations
SERVICES = mcp-gateway mock-server web

# Build flags
LDFLAGS = -X main.version=$(VERSION)

# Test configurations
TEST_PACKAGES ?= ./...
TEST_FLAGS ?= -v
COVERAGE_FILE ?= coverage.out
COVERAGE_HTML ?= coverage.html

# Registry targets
.PHONY: docker ghcr ali

# Build all services
.PHONY: build
build:
	@for service in $(SERVICES); do \
		docker build -t $(PROJECT_NAME)-$$service:$(IMAGE_TAG) \
			-f deploy/docker/multi/$$service/Dockerfile .; \
		docker tag $(PROJECT_NAME)-$$service:$(IMAGE_TAG) $(PROJECT_NAME)-$$service:latest; \
	done
	docker build -t $(PROJECT_NAME)-allinone:$(IMAGE_TAG) \
		-f deploy/docker/allinone/Dockerfile .
	docker tag $(PROJECT_NAME)-allinone:$(IMAGE_TAG) $(PROJECT_NAME)-allinone:latest

# Build multi-container version
.PHONY: build-multi
build-multi:
	@for service in $(SERVICES); do \
		docker build -t $(PROJECT_NAME)-$$service:$(IMAGE_TAG) \
			-f deploy/docker/multi/$$service/Dockerfile .; \
		docker tag $(PROJECT_NAME)-$$service:$(IMAGE_TAG) $(PROJECT_NAME)-$$service:latest; \
	done

# Build all-in-one version
.PHONY: build-allinone
build-allinone:
	docker build -t $(PROJECT_NAME)-allinone:$(IMAGE_TAG) \
		-f deploy/docker/allinone/Dockerfile .
	docker tag $(PROJECT_NAME)-allinone:$(IMAGE_TAG) $(PROJECT_NAME)-allinone:latest

# Run multi-container version
.PHONY: run-multi
run-multi:
	MCP_GATEWAY_IMAGE=$(MCP_GATEWAY_IMAGE) \
	MOCK_USER_SVC_IMAGE=$(MOCK_USER_SVC_IMAGE) \
	WEB_IMAGE=$(WEB_IMAGE) \
	docker-compose --env-file .env.multi --project-directory . -f deploy/docker/multi/docker-compose.yml up -d

# Stop multi-container version
.PHONY: stop-multi
stop-multi:
	docker-compose --env-file .env.multi --project-directory . -f deploy/docker/multi/docker-compose.yml stop

# Down multi-container version
.PHONY: down-multi
down-multi:
	docker-compose --env-file .env.multi --project-directory . -f deploy/docker/multi/docker-compose.yml down -v

# Run all-in-one version
.PHONY: run-allinone
run-allinone:
	IMAGE=$(IMAGE) docker-compose --env-file .env.allinone --project-directory . -f deploy/docker/allinone/docker-compose.yml up -d

# Stop all-in-one version
.PHONY: stop-allinone
stop-allinone:
	docker-compose --env-file .env.allinone --project-directory . -f deploy/docker/allinone/docker-compose.yml stop

# Down all-in-one version
.PHONY: down-allinone
down-allinone:
	docker-compose --env-file .env.allinone --project-directory . -f deploy/docker/allinone/docker-compose.yml down -v

# Push to Docker Hub
docker: build
	@for service in $(SERVICES); do \
		docker tag $(PROJECT_NAME)-$$service:$(IMAGE_TAG) \
			$(DOCKER_REGISTRY)/$(PROJECT_NAME)/$$service:$(IMAGE_TAG); \
		docker push $(DOCKER_REGISTRY)/$(PROJECT_NAME)/$$service:$(IMAGE_TAG); \
	done
	docker tag $(PROJECT_NAME)-allinone:$(IMAGE_TAG) \
		$(DOCKER_REGISTRY)/$(PROJECT_NAME)/allinone:$(IMAGE_TAG)
	docker push $(DOCKER_REGISTRY)/$(PROJECT_NAME)/allinone:$(IMAGE_TAG)

# Push to GitHub Container Registry
ghcr: build
	@for service in $(SERVICES); do \
		docker tag $(PROJECT_NAME)-$$service:$(IMAGE_TAG) \
			$(GHCR_REGISTRY)/$(PROJECT_NAME)/$$service:$(IMAGE_TAG); \
		docker push $(GHCR_REGISTRY)/$(PROJECT_NAME)/$$service:$(IMAGE_TAG); \
	done
	docker tag $(PROJECT_NAME)-allinone:$(IMAGE_TAG) \
		$(GHCR_REGISTRY)/$(PROJECT_NAME)/allinone:$(IMAGE_TAG)
	docker push $(GHCR_REGISTRY)/$(PROJECT_NAME)/allinone:$(IMAGE_TAG)

# Push to Alibaba Cloud Container Registry
ali: build
	@for service in $(SERVICES); do \
		docker tag $(PROJECT_NAME)-$$service:$(IMAGE_TAG) \
			$(ALI_REGISTRY)/$(PROJECT_NAME)/$$service:$(IMAGE_TAG); \
		docker push $(ALI_REGISTRY)/$(PROJECT_NAME)/$$service:$(IMAGE_TAG); \
	done
	docker tag $(PROJECT_NAME)-allinone:$(IMAGE_TAG) \
		$(ALI_REGISTRY)/$(PROJECT_NAME)/allinone:$(IMAGE_TAG)
	docker push $(ALI_REGISTRY)/$(PROJECT_NAME)/allinone:$(IMAGE_TAG)

# Test targets
.PHONY: test test-coverage test-race

# Run all tests
test:
	go test $(TEST_FLAGS) $(TEST_PACKAGES)

# Run tests with coverage
test-coverage:
	go test $(TEST_FLAGS) -coverprofile=$(COVERAGE_FILE) $(TEST_PACKAGES)
	go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)

# Run tests with race detection
test-race:
	go test $(TEST_FLAGS) -race $(TEST_PACKAGES)

# Clean up test artifacts
clean-test:
	rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)

# Clean up local images
.PHONY: clean
clean:
	@for service in $(SERVICES); do \
		docker rmi $(PROJECT_NAME)-$$service:$(IMAGE_TAG) || true; \
		docker rmi $(DOCKER_REGISTRY)/$(PROJECT_NAME)/$$service:$(IMAGE_TAG) || true; \
		docker rmi $(GHCR_REGISTRY)/$(PROJECT_NAME)/$$service:$(IMAGE_TAG) || true; \
		docker rmi $(ALI_REGISTRY)/$(PROJECT_NAME)/$$service:$(IMAGE_TAG) || true; \
	done
	docker rmi $(PROJECT_NAME)-allinone:$(IMAGE_TAG) || true
	docker rmi $(DOCKER_REGISTRY)/$(PROJECT_NAME)/allinone:$(IMAGE_TAG) || true
	docker rmi $(GHCR_REGISTRY)/$(PROJECT_NAME)/allinone:$(IMAGE_TAG) || true
	docker rmi $(ALI_REGISTRY)/$(PROJECT_NAME)/allinone:$(IMAGE_TAG) || true 