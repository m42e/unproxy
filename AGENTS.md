# Repository Guidelines

## Project Structure & Module Organization

Unproxy is a Rust 2024 crate. Shared runtime and platform code lives in `src/`; executable entry points are in `src/bin/`. Integration tests are in `tests/`, with test certificates and other fixtures in `tests/fixtures/`. Installer assets, PAC files, and tray icons are in `assets/`. User, installation, and release documentation is in `docs/`; CI helper scripts are in `scripts/`.

## Build, Test, and Development Commands

- `cargo build --locked --bins` builds all command-line and desktop binaries for development.
- `cargo build --release --locked --bins` produces optimized binaries, matching the documented release build.
- `cargo run --bin unproxy -- --help` runs the main executable and prints its options.
- `cargo fmt --all -- --check` checks formatting; `cargo clippy --locked --all-targets --all-features -- -D warnings` checks all targets with warnings treated as errors.
- `cargo test --locked --all-features` and `cargo test --locked --no-default-features` run the CI test configurations. `cargo xtask docs` and `cargo xtask package --format native` exercise the CI documentation and packaging workflows.

## Coding Style & Naming Conventions

Follow standard Rust formatting (four-space indentation, `snake_case` modules and functions, `UpperCamelCase` types) and keep changes idiomatic and platform-gated where needed. Run `cargo fmt` before submitting; use Clippy output to catch common mistakes. Keep binary names and source filenames consistent with the existing kebab-case entries in `src/bin/`.

## Testing Guidelines

Add or update integration tests in `tests/` for user-visible behavior and regressions; name files after the feature or module they cover, such as `tests/pac_routes.rs`. Use `tests/fixtures/` for stable test inputs. Check both default and no-default feature builds when changing feature-dependent behavior. CI also checks coverage with `scripts/check_coverage.py`.

## Commit & Pull Request Guidelines

Use a short imperative commit subject. The history includes conventional prefixes such as `feat:`, `fix:`, `test:`, and `docs:`; use one when it clarifies the change. Pull requests should explain the behavior changed, link a related issue when available, and report the relevant formatting, lint, and test results. Include screenshots for tray or desktop UI changes.

Always run every configured pre-commit check before committing, and never skip or bypass these checks (including with `--no-verify`, `SKIP`, or equivalent). If a check fails, resolve the failure before committing; do not disable or omit the check to get a commit through.

Always commit your changes if a job is finished. Never tell it is finished unless it has tests included.
