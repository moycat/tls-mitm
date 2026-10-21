# AGENTS.md

## Repository Overview

`tls-mitm` is a Rust 2021 command-line tool for authorized TLS testing. It reads SNI, signs a temporary server certificate with a configured CA, proxies application bytes to a TLS or plain TCP upstream, and optionally rewrites DNS answers and streams decrypted traffic as PCAP. Cargo manages the build; OpenSSL is required at runtime for certificate signing and by certificate tests. `.github/workflows/ci.yml` runs quality checks and a release build on Linux and macOS.

- `src/config.rs`: TOML loading and validation.
- `src/cert.rs`: CA validation, leaf signing, and certificate cache.
- `src/proxy.rs`: TLS listeners, route selection, upstream connections, and forwarding.
- `src/dns.rs`: UDP/TCP DNS rewrite, relay, and upstream name resolution.
- `src/capture.rs`: synthetic PCAP streams of decrypted traffic.
- `src/main.rs`: CLI setup and service startup; `tests/end_to_end.rs`: local integration tests.
- `example/config.toml`: runnable sample configuration; `example/certs/`: local test CA fixtures.

## Engineering Standards

- Follow current Rust and Tokio practices compatible with the crate's 2021 edition and supported toolchain. Prefer standard-library and existing crate APIs before adding dependencies.
- Keep configuration validation in `config.rs` and protocol-specific behavior in its existing module. Follow existing naming, error-context, and test patterns before adding abstractions.
- Keep changes small, cohesive, readable, and maintainable. Avoid speculative abstractions, unrelated refactors, dead code, and duplicated validation.
- Preserve upstream TLS certificate verification by default. An explicit route with `verify = false` is limited to controlled testing; do not broaden that bypass or silently disable verification.
- Keep DNS forwarding on the configured resolver and prevent it from pointing at this tool's DNS listener. Preserve UDP and TCP behavior, DNS response validation, timeouts, and bounded concurrency.
- Treat CA keys and decrypted PCAP as sensitive. Keep capture listeners on loopback by default; do not log private keys or application payloads. `example/certs/test.key.pem` is a local test fixture, not a production CA key.
- Keep `example/config.toml` pointed at committed test fixtures. Put machine-specific CA settings in ignored `config.local.toml` and pass it with `--config`.

## Language Policy

- Write new code, comments, agent notes, plans, and repository documentation in English. Existing Chinese README text is user-facing product documentation; preserve it unless the requested change calls for editing it. Product copy and i18n strings may use their intended language.
- Reply to the user in the language they use. Give subagents English prompts and request English reports.

## Subagent Workflow

- Use subagents aggressively for separable investigation, repository exploration, implementation, validation, and review. Split independent tasks when possible to preserve the main agent's context.
- Use the same model and comparable effort level as the main agent unless the user specifies otherwise. Coordinate shared-file edits to avoid conflicts.

## Quality Commands

After every code edit and before every commit, run the relevant checks from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --offline --all-targets --all-features -- -D warnings
cargo test --offline
```

Use `cargo check --offline --all-targets` for a quicker static build while developing, and `cargo build --release --offline` when a release binary matters. Review changed code for dead paths, unused dependencies, duplicated logic, and code smells; the repository has no dedicated dead-code checker. Do not claim network or device behavior from these local checks.

## Testing Expectations

- Add meaningful tests for new behavior and bug fixes using the existing inline Rust tests and `tests/end_to_end.rs`. Cover success, edge cases, and errors, especially configuration rejection, route matching, certificate verification, DNS UDP/TCP handling, and bidirectional capture.
- Prefer loopback listeners, ephemeral ports, local fixtures, and timeouts. Tests should not need a public network, privileged ports, or a real device.
- Do not replace the test CA fixture with a real CA or check in newly generated private keys.

## Commits

- Do not commit, push, or deploy unless the user asks. When asked to commit, use Conventional Commits such as `feat: add route option`, `fix: reject invalid DNS reply`, or `docs: initialize agent guidance`.
