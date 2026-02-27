# Enclaver developer shortcuts

CARGO ?= cargo
MANIFEST_PATH ?= enclaver/Cargo.toml
ALL_FEATURES ?= run_enclave,odyn
TRACING_FEATURES ?= run_enclave,odyn,tracing
ODYN_FEATURES ?= odyn

RUSTFLAGS_WARN ?= -Dwarnings
RUSTFLAGS_TRACING ?= --cfg=tokio_unstable -Dwarnings

.PHONY: help fmt fmt-check check lint lint-default lint-all lint-tracing test test-fast test-odyn build build-default build-all clean

help:
	@echo "Available targets:"
	@echo "  make fmt          - Format code"
	@echo "  make fmt-check    - Check formatting"
	@echo "  make check        - Cargo check (default features)"
	@echo "  make lint         - Clippy checks (default, full features, tracing)"
	@echo "  make test         - Run tests (default + odyn feature)"
	@echo "  make build        - Build (default features)"
	@echo "  make build-all    - Build with $(ALL_FEATURES)"
	@echo "  make clean        - Clean build artifacts"

fmt:
	$(CARGO) fmt --all --manifest-path $(MANIFEST_PATH)

fmt-check:
	$(CARGO) fmt --all --manifest-path $(MANIFEST_PATH) --check

check:
	$(CARGO) check --manifest-path $(MANIFEST_PATH)

lint-default:
	RUSTFLAGS="$(RUSTFLAGS_WARN)" $(CARGO) clippy --no-deps --manifest-path $(MANIFEST_PATH) -- -D warnings

lint-all:
	RUSTFLAGS="$(RUSTFLAGS_WARN)" $(CARGO) clippy --no-deps --manifest-path $(MANIFEST_PATH) --features=$(ALL_FEATURES) -- -D warnings

lint-tracing:
	RUSTFLAGS="$(RUSTFLAGS_TRACING)" $(CARGO) clippy --no-deps --manifest-path $(MANIFEST_PATH) --features=$(TRACING_FEATURES) -- -D warnings

lint: lint-default lint-all lint-tracing

test-fast:
	$(CARGO) test --manifest-path $(MANIFEST_PATH)

test-odyn:
	$(CARGO) test --manifest-path $(MANIFEST_PATH) --features=$(ODYN_FEATURES)

test: test-fast test-odyn

build-default:
	$(CARGO) build --manifest-path $(MANIFEST_PATH)

build-all:
	$(CARGO) build --manifest-path $(MANIFEST_PATH) --features=$(ALL_FEATURES)

build: build-default

clean:
	$(CARGO) clean --manifest-path $(MANIFEST_PATH)
