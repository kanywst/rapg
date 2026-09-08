.PHONY: build run test clean fmt vet install demo

BINARY_NAME=rapg
MAIN_PATH=./cmd/rapg

# Reported by `rapg version`. Falls back to "dev" outside a git checkout.
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS=-X github.com/kanywst/rapg/internal/version.Version=$(VERSION)

# Build the binary
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) $(MAIN_PATH)

# Run properly (interactive)
run:
	go run $(MAIN_PATH)

# Run tests
test:
	go test -v ./...

# Format code
fmt:
	go fmt ./...

# Static analysis
vet:
	go vet ./...

# Install to GOPATH/bin
install:
	go install -ldflags "$(LDFLAGS)" $(MAIN_PATH)

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/
	rm -f coverage.out
	rm -f demo-v2.gif

# Update the demo GIF (requires vhs).
# Builds the binary first so demo.tape doesn't have to (avoids Hide-block leaks).
demo: build
	vhs demo.tape
