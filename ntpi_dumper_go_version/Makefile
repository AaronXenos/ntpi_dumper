# Makefile for NTPI Dumper Go (cross-platform)

.PHONY: all build clean test deps run

# Build variables
BINARY_NAME=ntpi-dumper
MAIN_PATH=./cmd/ntpi-dumper
BUILD_FLAGS=-ldflags="-s -w"

# Default target
all: deps build

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Build for current platform
build:
	@echo "Building $(BINARY_NAME)..."
	go build $(BUILD_FLAGS) -o $(BINARY_NAME) $(MAIN_PATH)
	@echo "Build complete: $(BINARY_NAME)"

# Build for all platforms
build-all: build-windows build-linux build-macos

build-windows:
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o $(BINARY_NAME).exe $(MAIN_PATH)

build-linux:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $(BINARY_NAME)-linux $(MAIN_PATH)

build-macos:
	@echo "Building for macOS..."
	GOOS=darwin GOARCH=amd64 go build $(BUILD_FLAGS) -o $(BINARY_NAME)-macos $(MAIN_PATH)

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe $(BINARY_NAME)-linux $(BINARY_NAME)-macos
	rm -rf .temp *_extracted

# Run the program (requires NTPI file as argument)
run: build
	./$(BINARY_NAME) $(ARGS)

# Install to system
install: build
	@echo "Installing..."
	go install $(MAIN_PATH)

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run
