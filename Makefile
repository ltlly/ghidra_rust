.PHONY: build test run fmt lint docs clean install

# Default target
build:
	cargo build

test:
	cargo test

run:
	cargo run

fmt:
	cargo fmt

lint:
	cargo clippy --all-targets --all-features -- -D warnings

docs:
	cargo doc --no-deps --open

clean:
	cargo clean

install:
	cargo install --path .
