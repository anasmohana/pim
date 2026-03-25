.PHONY: build install clean test fmt

# Build the binary
build:
	go build -o pim ./cmd/pim

# Install to GOPATH/bin
install:
	go install ./cmd/pim

# Clean build artifacts
clean:
	rm -f pim
	go clean

# Run tests
test:
	go test ./...

# Format code
fmt:
	go fmt ./...

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o pim-linux-amd64 ./cmd/pim
	GOOS=darwin GOARCH=amd64 go build -o pim-darwin-amd64 ./cmd/pim
	GOOS=darwin GOARCH=arm64 go build -o pim-darwin-arm64 ./cmd/pim
	GOOS=windows GOARCH=amd64 go build -o pim-windows-amd64.exe ./cmd/pim

# Run the tool
run:
	go run ./cmd/pim $(ARGS)
