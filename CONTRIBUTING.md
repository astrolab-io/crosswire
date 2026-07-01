# Contributing to CrossWire

Thanks for your interest in improving CrossWire! This project is a
provider-agnostic PPP-over-TLS VPN client; contributions of bug fixes, new
providers, platform support, and documentation are all welcome.

## Ground rules

- **License.** CrossWire is `GPL-3.0-or-later`. By contributing you agree your
  work is licensed the same way. Start every new source file with:
  ```
  // SPDX-License-Identifier: GPL-3.0-or-later
  ```
- **Be respectful** and assume good faith in reviews and discussions.
- **Security issues:** please report privately (see the repository's Security
  policy) rather than opening a public issue.

## Development setup

```sh
git clone https://github.com/astrolab-io/crosswire
cd crosswire
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

CI runs `fmt`, `clippy -D warnings`, and `cargo test` on every push and PR; please
run them locally first. Actually connecting a tunnel needs root and `pppd`.

## Making a change

1. Branch off `main`.
2. Keep commits focused; write clear messages (imperative subject, a body
   explaining *why*). Do **not** add `Co-authored-by` trailers for automated
   tooling.
3. Add or update tests. Prefer **pure, unit-testable** functions for parsing and
   argv/route/DNS mapping — that is where regressions hide.
4. Ensure `cargo fmt`, `cargo clippy -D warnings`, and `cargo test` all pass.
5. Open a PR describing the change and how you verified it. If it affects a live
   connection, say what gateway/OS you tested against.

## Adding a VPN provider

CrossWire's core is deliberately provider-agnostic. A new provider implements the
`VpnProvider` trait in `src/core/provider.rs`:

- `authenticate` — obtain a session (credentials, SSO, cookie, …).
- `fetch_params` — return the `TunnelParams` (address, DNS, split routes, MTU).
- `open_tunnel` — hand back the transport the io-loop drives.

Put provider code under `src/providers/<name>/`, register it in
`src/providers/mod.rs`, and keep everything gateway-specific there — the engine,
network layer, and transport must stay generic. See `src/providers/fortinet/` as
the reference implementation.

## Cross-project contract

When CrossWire runs under
[crosswire-network-manager](https://github.com/astrolab-io/crosswire-network-manager),
it hands split routes and DNS to the pppd plugin through the `CROSSWIRE_*`
environment variables. That format is a **contract tested on both sides** — if
you change it, update the producer test (`transport::ppp::tests`) *and* the
plugin's consumer test, and the contract doc in that repo.

## Coding style

- Match the surrounding code; run `cargo fmt`.
- Keep comments about *why*, not *what*.
- No `unwrap()`/`expect()` on paths that can fail at runtime; return `Result` and
  add context with `anyhow`.
