VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64

.PHONY: all manager nodes test test-all clean
all: manager nodes

manager:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/radman-manager ./cmd/manager

# Node binaries are served to users by the manager's "download site node" button.
nodes:
	@mkdir -p dist/nodes
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=""; [ $$os = windows ] && ext=".exe"; \
	  echo "building node $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS) -X radman/internal/nodeagent.Version=$(VERSION)" \
	    -o dist/nodes/radman-node_$${os}_$${arch}$$ext ./cmd/node || exit 1; \
	done

test:
	go test ./...

# The manager integration tests need PostgreSQL (RADMAN_TEST_DB) and run once per edition.
test-all:
	RADMAN_TEST_MODE=msp go test -count=1 ./...
	RADMAN_TEST_MODE=standalone go test -count=1 ./...

clean:
	rm -rf dist
