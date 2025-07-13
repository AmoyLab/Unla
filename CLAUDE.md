# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Unla is an MCP (Model Context Protocol) Gateway service written in Go with a React/TypeScript web interface. It acts as a lightweight proxy and management layer that converts existing APIs and MCP servers into MCP-compliant services through configuration-driven approaches.

**Key Architecture:**
- **Control Plane**: `cmd/apiserver` - REST API server for management, configuration, and web UI backend
- **Data Plane**: `cmd/mcp-gateway` - MCP proxy gateway handling real-time MCP protocol communication
- **Web Interface**: `web/` - React/TypeScript dashboard for configuration and chat

## Development Commands

### Go Backend

```bash
# Run tests
make test
make test-coverage  # with coverage report
make test-race     # with race detection

# Build all services
make build

# Build specific components
make build-allinone   # single container
make build-multi      # multi-container

# Run services locally
make run-allinone     # single container setup
make run-multi        # multi-container setup

# Development - run specific services
go run cmd/apiserver/main.go -c configs/apiserver.yaml
go run cmd/mcp-gateway/main.go -c configs/mcp-gateway.yaml
go run cmd/mock-server/main.go

# Configuration testing
go run cmd/mcp-gateway/main.go test -c configs/mcp-gateway.yaml
```

### Web Frontend

```bash
cd web/
pnpm run dev          # development server
pnpm run build        # production build
pnpm run lint         # lint TypeScript/React code
pnpm run preview      # preview production build
```

## Key Architecture Components

### Service Architecture
- **apiserver**: Database-backed management API with JWT auth, user/tenant management, OpenAI integration
- **mcp-gateway**: Stateless proxy service with hot-reloading configs, multiple transport support (SSE, stdio, HTTP)
- **Web Dashboard**: React SPA for configuration management and MCP chat interface

### Transport Layer
- **SSE (Server-Sent Events)**: Real-time bidirectional communication
- **Stdio**: Local process execution for MCP servers
- **Streamable HTTP**: HTTP-based streaming protocol
- All transports implement the same interface for tool fetching/calling

### Configuration Management
- YAML-based configuration with environment variable substitution (`${VAR:default}`)
- Hot-reloading via SIGHUP signals or HTTP endpoints
- Version control and rollback support
- Multi-tenant scoped configurations

### Storage Backends
- **Database**: SQLite/MySQL/PostgreSQL via GORM
- **Disk**: File-based YAML configurations
- **Redis**: Session storage and real-time notifications
- **Memory**: In-memory caching and state management

## Code Organization Patterns

### Go Backend Structure
- `internal/core/`: Core MCP proxy logic, transport implementations, state management
- `internal/apiserver/`: REST API handlers, database models, middleware
- `internal/common/`: Shared configuration, DTOs, constants, error handling
- `internal/auth/`: OAuth2 and JWT authentication logic
- `internal/mcp/`: MCP protocol storage and session management
- `pkg/`: Reusable packages (logger, OpenAI client, utilities)

### Configuration Files
- `configs/mcp-gateway.yaml`: Gateway service configuration
- `configs/apiserver.yaml`: API server configuration  
- `configs/i18n/`: Internationalization files (English/Chinese)

### Frontend Structure
- `src/pages/`: Route-based page components (auth, chat, gateway management)
- `src/components/`: Reusable UI components with HeroUI framework
- `src/services/`: API clients and WebSocket connections
- `src/types/`: TypeScript type definitions
- Uses React Router, i18next for internationalization, Monaco Editor for YAML editing

## Development Guidelines

### Code Style (from .cursorrules)
- All comments must be in English and only where code is not self-explanatory
- Avoid redundant or obvious comments
- Before writing new code, check if similar functionality exists and follow existing patterns
- Prioritize understanding existing infrastructure over building from scratch

### Service Selection
- **Modification target**: Determine if changes belong to control plane (`cmd/apiserver`) or data plane (`cmd/mcp-gateway`)
- **apiserver**: Management UI, user auth, configuration persistence, chat functionality
- **mcp-gateway**: Real-time MCP protocol handling, tool calling, transport management

### Architecture Patterns
- **Chain of Responsibility**: Response handling (ImageHandler -> AudioHandler -> TextHandler)
- **Factory Pattern**: Multiple storage backends and transport implementations
- **State Management**: Atomic updates with lock-free state replacement
- **Configuration Hot-Reloading**: File watchers and signal-based updates

## Testing and Quality

### Go Testing
```bash
make test                    # run all tests
make test-coverage          # generate coverage report
make test-race              # test with race detection
go test ./pkg/utils/...     # test specific packages
```

### Configuration Validation
```bash
# Test configuration before deployment
go run cmd/mcp-gateway/main.go test -c configs/mcp-gateway.yaml
```

### Operational Commands
```bash
# Live reload configuration
go run cmd/mcp-gateway/main.go reload -c configs/mcp-gateway.yaml

# Check service status  
curl http://localhost:5234/health
```

## Deployment

The project supports multiple deployment patterns:
- **All-in-one**: Single container with all services
- **Multi-container**: Separate containers for each service
- **Kubernetes**: Helm charts available in `deploy/helm/`
- **Docker Compose**: Multiple configurations in `deploy/docker/`

Environment variables are heavily used for configuration with Docker deployments. Check the Makefile and deployment configurations for specific setup requirements.