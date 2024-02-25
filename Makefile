.DEFAULT_GOAL := help

ifeq ($(GOPATH),)
	GOPATH := $(shell pwd)
endif

export GOPATH

BIN_NAME := ra

.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build-mac       Build for macOS"
	@echo "  build-linux     Build for Linux"
	@echo "  clean           Clean build artifacts"
	@echo "  help            Show this help message"

.PHONY: build-mac
build-mac:
	@echo "Building for macOS..."
	GOOS=darwin GOARCH=amd64 go build -o ${GOPATH}/$(BIN_NAME) cmd/rapg/main.go

.PHONY: build-linux
build-linux:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 go build -o $(GOPATH)/$(BIN_NAME).linux cmd/rapg/main.go

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(GOPATH)
