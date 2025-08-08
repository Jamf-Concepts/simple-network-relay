# Copyright (c) 2025 JAMF Software, LLC
EXECUTABLE = simple-network-relay
CLIENT_CONFIG_PROFILE="relay.mobileconfig"
HOST := $(shell hostname)

default: configure test build run

check:
	@echo "--- Running linters"
ifeq (, $(shell which golangci-lint))
	@echo "golangci-lint is missing on your system. Install it first: https://golangci-lint.run/welcome/install/#local-installation"; exit 1
endif
	golangci-lint run

configure:
	@echo "--- Generating config & certificates"
	script/generate_mobileconfig.sh
	script/generate_certificates.sh > /dev/null

test:
	@echo "\n--- Running tests"
	go test ./...

build:
	@echo "\n--- Running build"
	go build -v -o "bin/$(EXECUTABLE)"
	go mod tidy

run:
	@echo "\n--- Starting the relay"
	QUIC_GO_LOG_LEVEL=INFO ./bin/$(EXECUTABLE)

clean:
	@echo "--- Cleaning up"
	rm -rf cert/
	rm -f relay.mobileconfig
