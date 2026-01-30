#!/bin/bash
set -e

echo "=== Building eBPF Program ==="
rustup toolchain install nightly
cargo +nightly build --package ids-xdp --target bpfel-unknown-none --release -Z build-std=core

echo "=== Building User Space Program ==="
cargo build --release

echo "=== Build Complete ==="
echo "Run with: sudo ./target/release/ids_rust -c config.yaml -i <INTERFACE>"
