# SIGN_ID="Apple Development: you@example.com (TEAMID)" gives the macOS binary a stable identity (keychain won't re-prompt after rebuilds)
SIGN_ID ?= -
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS = -X main.version=$(VERSION)

.PHONY: all test unit clean install unlockfs unlockfs-test
all: unlockfs

unlockfs:
	go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/unlockfs
	@if [ "$$(uname)" = Darwin ]; then codesign -f -s "$(SIGN_ID)" $@; fi

# test-only build: UNLOCKFS_AUTH=test replaces the prompt with a control file. Never install this binary.
unlockfs-test:
	go build -tags unlockfs_testing -ldflags "$(LDFLAGS)" -o $@ ./cmd/unlockfs

unit:
	go vet ./... && go test ./internal/...

test: unit unlockfs-test
	./test/run.sh

install: unlockfs
	./contrib/install-launchd.sh

clean:
	rm -rf unlockfs unlockfs-test test/.run test/.run-touchid
