#!/usr/bin/env bash
# HNK-16: one local command that runs every check CI runs. Exits non-zero on the first failure.
#   bash scripts/check.sh            # everything
#   SKIP_WASM=1 bash scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n== %s\n' "$*"; }

step "cargo fmt --check";   cargo fmt --all -- --check
step "cargo check";         cargo check --workspace --all-targets --locked
step "cargo clippy";        cargo clippy --workspace --all-targets --locked -- -D warnings
step "cargo test";          cargo test --workspace --locked

if [ "${SKIP_WASM:-0}" != "1" ]; then
  step "wasm build"
  rustup target add wasm32-unknown-unknown >/dev/null
  cargo build -p jitsuin-wasm --target wasm32-unknown-unknown --release --locked
fi

step "secret scan"
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks git --redact --no-banner --exit-code 1 .
else
  echo "gitleaks not installed locally; CI runs it on every push (https://github.com/gitleaks/gitleaks/releases)."
fi

printf '\nAll checks passed.\n'
