.PHONY: build run test clean fmt vet install demo

BINARY_NAME=rapg
MAIN_PATH=./cmd/rapg

# Build the binary
build:
	go build -o $(BINARY_NAME) $(MAIN_PATH)

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
	go install $(MAIN_PATH)

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/
	rm -f coverage.out
	rm -f demo.gif

# Update the demo GIF (requires vhs).
# Builds the binary first so demo.tape doesn't have to (avoids Hide-block leaks).
demo: build
	vhs demo.tape
