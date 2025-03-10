.PHONY: all build clean test lint doc run package release install help

# Variables
CARGO := cargo
NAME := nanovm
VERSION := $(shell grep "^version" Cargo.toml | cut -d '"' -f2)
RELEASE_DIR := target/release
DEBUG_DIR := target/debug
CONFIG_FILE := nanovm_config.yaml

# Default features for enterprise build
FEATURES := enterprise

# Determine OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	OS := linux
else ifeq ($(UNAME_S),Darwin)
	OS := macos
else
	OS := unknown
endif

# Determine architecture
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	ARCH := x86_64
else ifeq ($(UNAME_M),aarch64)
	ARCH := aarch64
else ifeq ($(UNAME_M),arm64)
	ARCH := aarch64
else
	ARCH := unknown
endif

# Default is to build in development mode
all: build

# Build the project
build:
	$(CARGO) build

# Build with release optimizations
release:
	$(CARGO) build --release --features $(FEATURES)

# Build specifically for production deployment
production:
	$(CARGO) build --profile production --features $(FEATURES)

# Clean the project
clean:
	$(CARGO) clean

# Run tests
test:
	$(CARGO) test --all-features --all-targets

# Run integration tests
integration-test:
	$(CARGO) test --test '*' -- --ignored

# Run the linter
lint:
	$(CARGO) clippy -- -D warnings

# Format code
format:
	$(CARGO) fmt

# Generate documentation
doc:
	$(CARGO) doc --no-deps --all-features

# Run with default configuration
run:
	$(CARGO) run -- --config $(CONFIG_FILE)

# Security audit
audit:
	cargo audit

# Build package
package: release
	mkdir -p dist
	cp $(RELEASE_DIR)/$(NAME) dist/
	cp $(CONFIG_FILE) dist/
	cd dist && tar -czf $(NAME)-$(VERSION)-$(ARCH)-$(OS).tar.gz $(NAME) $(CONFIG_FILE)
	@echo "Package created: dist/$(NAME)-$(VERSION)-$(ARCH)-$(OS).tar.gz"

# Install the package
install: release
	@echo "Installing $(NAME) to /usr/local/bin..."
	sudo install -m 0755 $(RELEASE_DIR)/$(NAME) /usr/local/bin/
	@echo "Creating configuration directory..."
	sudo mkdir -p /etc/$(NAME)
	@if [ ! -f /etc/$(NAME)/$(CONFIG_FILE) ]; then \
		echo "Installing default configuration..."; \
		sudo install -m 0644 $(CONFIG_FILE) /etc/$(NAME)/; \
	else \
		echo "Configuration already exists, not overwriting"; \
	fi

# Build Docker image
docker-build:
	docker build -t $(NAME):$(VERSION) .

# Run in Docker
docker-run:
	docker run -p 8080:8080 -p 443:443 -v $(PWD)/$(CONFIG_FILE):/etc/nanovm/nanovm_config.yaml $(NAME):$(VERSION)

# Start with docker-compose
docker-compose-up:
	docker-compose up -d

# Stop docker-compose services
docker-compose-down:
	docker-compose down

# Build and run with specific features
run-with-features:
	@echo "Available features: tls, mtls, metrics, tracing, advanced-security, enterprise"
	@read -p "Enter features to enable (comma-separated): " features; \
	$(CARGO) run --features $$features -- --config $(CONFIG_FILE)

# Print version information
version:
	@echo "$(NAME) version $(VERSION)"
	@echo "Build for $(OS)-$(ARCH)"
	$(CARGO) --version
	rustc --version

# Help command
help:
	@echo "NanoVM - Enterprise-grade rootless virtualization system"
	@echo ""
	@echo "Usage:"
	@echo "  make [command]"
	@echo ""
	@echo "Commands:"
	@echo "  build            Build the project in debug mode"
	@echo "  release          Build with release optimizations"
	@echo "  production       Build specifically for production deployment"
	@echo "  clean            Clean build artifacts"
	@echo "  test             Run tests"
	@echo "  integration-test Run integration tests"
	@echo "  lint             Run the linter"
	@echo "  format           Format code"
	@echo "  doc              Generate documentation"
	@echo "  run              Run with default configuration"
	@echo "  audit            Run security audit"
	@echo "  package          Create distributable package"
	@echo "  install          Install locally"
	@echo "  docker-build     Build Docker image"
	@echo "  docker-run       Run in Docker"
	@echo "  docker-compose-up Start with docker-compose"
	@echo "  docker-compose-down Stop docker-compose services"
	@echo "  run-with-features Run with specific features"
	@echo "  version          Print version information"
	@echo "  help             Print this help message" 