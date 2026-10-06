alias a := audit
alias b := build
alias c := check
alias d := docs
alias do := docs-open
alias f := fmt
alias l := lock
alias t := test
alias ta := test-all
alias z := zizmor
alias p := pre-push

export RBMT_LOG_LEVEL := env("RBMT_LOG_LEVEL", "verbose")

_default:
    @echo "> koerier"
    @echo "> A self-hosted lightning address server for LND\n"
    @just --list

[doc: "Run cargo-audit across all lockfiles"]
audit:
    @echo "Auditing Cargo.lock"
    cargo audit -D warnings --file Cargo.lock
    @echo "\nAuditing Cargo-maximum.lock"
    cargo audit -D warnings --file Cargo-maximum.lock
    @echo "\nAuditing Cargo-recent.lock"
    cargo audit -D warnings --file Cargo-recent.lock
    @echo "\nAuditing Cargo-minimal.lock"
    cargo audit -D warnings --file Cargo-minimal.lock

[doc: "Build `koerier`"]
build:
    cargo rbmt run build

[doc: "Check Formatting, Linting and Documentation"]
check:
    RBMT_LOG_LEVEL=progress cargo rbmt fmt --check
    RBMT_LOG_LEVEL=progress cargo rbmt lint
    RBMT_LOG_LEVEL=progress cargo rbmt docs

[doc: "Generate Documentation"]
docs:
    RBMT_LOG_LEVEL=progress cargo rbmt docs

[doc: "Generate and Open Documentation"]
docs-open:
    RBMT_LOG_LEVEL=progress cargo rbmt docs --open

[doc: "Format Code"]
fmt:
    RBMT_LOG_LEVEL=progress cargo rbmt fmt

[doc: "Regenerate Lockfiles"]
lock:
    cargo rbmt lock --lockfiles minimal,recent,maximum

[doc: "Run Tests"]
test:
    cargo rbmt test

[doc: "Run Tests with Lockfile and Toolchain Combos"]
test-all:
    cargo rbmt test  --toolchain msrv --lockfile minimal
    cargo rbmt test  --toolchain stable --lockfile recent
    cargo rbmt test  --toolchain stable --lockfile maximum

[doc: "Run Zizmor"]
zizmor:
    zizmor .

[doc: "Run pre-push checks"]
pre-push:
    @just lock
    @just check
    @just docs
    @just test
    @just audit
    @just zizmor
