REPO    = github.com/kiiimatz/reno
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS = -s -w -X main.version=$(VERSION)

PLATFORMS = \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

.PHONY: all build release clean

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o dist/reno ./cmd/reno

release:
	mkdir -p dist
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} ; \
		ext="" ; [ "$$GOOS" = "windows" ] && ext=".exe" ; \
		echo "Building reno $$GOOS/$$GOARCH..." ; \
		GOOS=$$GOOS GOARCH=$$GOARCH go build -ldflags "$(LDFLAGS)" \
			-o dist/reno-$$GOOS-$$GOARCH$$ext ./cmd/reno ; \
	done

clean:
	rm -rf dist/
