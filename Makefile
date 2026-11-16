GO        ?= go
BIN       ?= bin
FUZZTIME  ?= 30s
EXT       := $(if $(filter Windows_NT,$(OS)),.exe,)

.PHONY: all build vet test race bench fuzz check clean demo demo-gif

all: vet test build

build:
	$(GO) build -o $(BIN)/ifcproxy$(EXT) ./cmd/ifcproxy

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

# The race detector needs cgo (a C compiler).
race:
	$(GO) test -race ./...

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./internal/monitor ./internal/proxy
	$(GO) test -run TestDecideP99 -v ./internal/monitor

fuzz:
	$(GO) test -run '^$$' -fuzz FuzzParse -fuzztime $(FUZZTIME) ./internal/policy
	$(GO) test -run '^$$' -fuzz FuzzClientDifferential -fuzztime $(FUZZTIME) ./internal/proxy

check: build
	$(BIN)/ifcproxy$(EXT) --policy examples/policy.yaml --check

clean:
	rm -rf $(BIN)

# Play the lethal-trifecta attack against a real proxy.
demo:
	$(GO) run ./examples/trifecta-demo

# Regenerate the README animation (needs Python with Pillow).
demo-gif:
	$(GO) run ./examples/trifecta-demo > $(BIN)/demo.ans
	python scripts/render_demo_gif.py $(BIN)/demo.ans docs/demo.gif
