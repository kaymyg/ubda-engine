# Contributing to UBDA

Thanks for your interest in this project — it started as a self-teaching
exercise in capability-based access-control design, and contributions,
questions, and critiques are all welcome.

## Getting set up

Requires a stable Rust toolchain (2021 edition; tested against rustc 1.75+).

```bash
git clone https://github.com/kaymyg/ubda-engine.git
cd ubda-engine
cargo build
cargo test
cargo run
```

## Before opening a PR

Please run the same checks CI runs, so review focuses on the actual change:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

If `cargo fmt --check` fails, just run `cargo fmt` to fix it in place.

## What to work on

Good starting points:

- Anything in the "Known simplifications" section of
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Additional unit tests for edge cases not yet covered
- Clearer error messages or documentation
- A real (non-mock) `KeyAuthority` backend, e.g. against a software TEE
  simulator

For anything bigger than a small fix, please open an issue first to discuss
the approach before investing time in a PR.

## Commit style

Small, focused commits with a clear one-line summary are preferred over one
large commit. No strict format is enforced beyond that.

## Reporting bugs / requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/`. For security-relevant
findings, please see [`SECURITY.md`](SECURITY.md) instead of opening a public
issue.

## Code of conduct

Be respectful and constructive. This is a small educational project — the bar
is "would a reasonable person feel welcome contributing here."
