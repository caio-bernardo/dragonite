# Simple Makefile for a Go project

# Build the application
all: build test

build:
	@echo "Building..."


	@go build -o main cmd/api/main.go

# Run the application
run:
	@go run cmd/api/main.go
# Create DB container
docker-run:
	@if docker compose up --build 2>/dev/null; then \
		: ; \
	else \
		echo "Falling back to Docker Compose V1"; \
		docker-compose up --build; \
	fi

# Shutdown DB container
docker-down:
	@if docker compose down 2>/dev/null; then \
		: ; \
	else \
		echo "Falling back to Docker Compose V1"; \
		docker-compose down; \
	fi

# Test the application
test:
	@echo "Testing..."
	@go test ./... -v
# Integrations Tests for the application
itest:
	@echo "Running integration tests..."
	@go test ./internal/database -v

# Clean the binary
clean:
	@echo "Cleaning..."
	@rm -f main

# Create element client
client:
	@docker run --name local-element -d -p '8070:80' 'vectorim/element-web:latest'

# Drop element client
drop-client:
	@docker rm -f local-element

# Open element client in browser
open-client: client
	@xdg-open 'http://localhost:8070'

# Live Reload
watch:
	@if command -v air > /dev/null; then \
            air -c air.toml; \
            echo "Watching...";\
        else \
            read -p "Go's 'air' is not installed on your machine. Do you want to install it? [Y/n] " choice; \
            if [ "$$choice" != "n" ] && [ "$$choice" != "N" ]; then \
                go install github.com/air-verse/air@latest; \
                air -c air.toml; \
                echo "Watching...";\
            else \
                echo "You chose not to install air. Exiting..."; \
                exit 1; \
            fi; \
        fi

watch-fed:
	@echo "Starting federated server B"
	@env $$(cat .env.fed | grep -v '^#' | xargs) air -c air.toml
watch-fed2:
	@env $$(cat .env.fed2 | grep -v '^#' | xargs) air -c air.toml

.PHONY: all build run test clean watch docker-run docker-down itest client drop-client open-client run-fed
