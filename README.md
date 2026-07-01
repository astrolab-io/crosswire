<h1 align="center">CrossWire</h1>

<p align="center">
  <strong>A generic PPP-over-TLS VPN client, written in Rust, with pluggable providers.</strong><br>
  <em>FortiGate SSL-VPN is the first supported provider.</em>
</p>

<p align="center">
  <a href="https://www.gnu.org/licenses/gpl-3.0"><img alt="License: GPL v3" src="https://img.shields.io/badge/License-GPLv3-blue.svg"></a>
  <img alt="Status: beta" src="https://img.shields.io/badge/status-beta-orange.svg">
</p>

---

CrossWire connects to SSL-VPN gateways that tunnel PPP over TLS. The pipeline —
**connect → authenticate → configure network → tunnel → tear down** — is
**provider-agnostic**; everything gateway-specific lives behind a small
`VpnProvider` trait. Today that provider is **FortiGate**; the architecture is
built so others can be added without touching the core.

It is inspired by, and reuses protocol lessons from,
[`openfortivpn`](https://github.com/adrienverge/openfortivpn) — all credit for
the FortiGate protocol logic goes to Adrien Vergé and its contributors. CrossWire
is licensed GPLv3 to match.

> **Desktop / NetworkManager users:** you probably want
> **[crosswire-network-manager](https://github.com/astrolab-io/crosswire-network-manager)**,
> which wraps CrossWire as a NetworkManager VPN plugin (connect from the GNOME/KDE
> network menu, SSO in your browser, split-tunnel, split-DNS).

## Features

- **Auth:** username/password, **SAML/SSO** (opens your browser), session cookie,
  and **OTP/2FA** including FortiToken Mobile push.
- **TLS:** system-store PKI verification **or** certificate pinning by SHA-256
  digest, `--ca-file`, `--min-tls`, `--cipher-list`, mutual-TLS client certs
  (PEM or `pkcs11:` URIs behind `--features pkcs11`).
- **Networking:** split- and full-tunnel routing, split-DNS, gateway-route
  protection so the tunnel never swallows its own transport, and
  `--set-routes` / `--set-dns` / `--set-ip` toggles to delegate any of it to an
  external manager.
- **Robust by construction:** every exit path restores routes, DNS, and the
  assigned address, reaps the `pppd` child, and logs the gateway out — via RAII
  guards. SIGINT/SIGTERM tear down gracefully; `--persistent N` reconnects.
- **Portable:** `pppd` on Linux, `ppp -direct` on BSD/macOS; DNS/route/browser
  backends are pluggable, not hardwired to systemd.

## Install

### From a release

Prebuilt archives, `.deb`, and `.rpm` are attached to each
[GitHub release](https://github.com/astrolab-io/crosswire/releases):

```sh
sudo dpkg -i crosswire_*_amd64.deb      # Debian/Ubuntu
sudo rpm -i  crosswire-*.x86_64.rpm     # Fedora/RHEL
```

### From source

```sh
cargo build --release                     # → target/release/crosswire
cargo build --release --features pkcs11   # + PKCS#11 client certs (optional)
sudo install -Dm755 target/release/crosswire /usr/sbin/crosswire
```

**Runtime requirements** (CrossWire must run as root):

- **Linux:** `pppd`, `ip`, and one of `resolvectl` / `resolvconf` (falls back to
  editing `/etc/resolv.conf`). For SSO, a browser opener (`xdg-open`).
- **macOS/BSD:** `ppp`, `route`, `ifconfig`; for SSO, `open`.

## Usage

```sh
# Username / password
sudo crosswire vpn.example.com:443 -u alice -p 's3cr3t'

# SSO — opens your browser, local callback on port 8020
sudo crosswire vpn.example.com --saml-login

# One-time password (2FA)
sudo crosswire vpn.example.com -u alice -p 's3cr3t' -o 123456

# Pre-obtained session cookie
sudo crosswire vpn.example.com --cookie 'SVPNCOOKIE=…'

# Pin the gateway certificate and reconnect forever
sudo crosswire vpn.example.com --trusted-cert <sha256> --persistent 5
```

Options may also come from `/etc/crosswire/config` (or `-c <file>`) as
`key = value` lines (`host`, `trusted-cert`, `set-dns`, `realm`, …). Run
`crosswire --help` for the complete list.

### PKCS#11 (smart-card / HSM client certs)

```sh
cargo build --release --features pkcs11
sudo crosswire vpn.example.com \
  --user-cert 'pkcs11:object=…;type=cert' \
  --user-key  'pkcs11:object=…;type=private'
```

Requires the system OpenSSL `pkcs11` engine (`libengine-pkcs11-openssl`) and a
PKCS#11 module such as OpenSC.

## How it works

```
core::Engine (provider-agnostic)
  connect TLS → provider.authenticate → provider.fetch_params →
  NetworkConfigurator.apply(guards) → provider.open_tunnel →
  Link(PPP) ⇄ Transport(codec) io-loop → (signal / error) → teardown
```

- **`core/`** — the `VpnProvider` / `AuthMethod` traits, the engine pipeline, the
  io-loop, and cooperative shutdown.
- **`transport/`** — TLS (pinning + PKI, cipher/version options, client certs),
  the platform PPP spawner, the HDLC and Fortinet `0x5050` framers, the async pty.
- **`net/`** — `NetworkConfigurator` with restore-on-drop guards, Linux and
  BSD/macOS backends, and a portable SSO browser launcher.
- **`providers/fortinet/`** — HTTP client + cookie jar, logincheck/SAML/OTP auth,
  and `fortisslvpn` config parsing.

> **Portability note:** the BSD/macOS PPP and network backends are
> platform-dispatched, compiled on all targets, and unit-tested (argv builders,
> route/DNS parsers), but have not yet been exercised on a live BSD/macOS host.

## Building & testing

```sh
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for how to
build, test, add a provider, and submit changes.

## License

Copyright © 2026 the CrossWire authors.

CrossWire is free software under the **GNU General Public License, version 3 or
later** (`GPL-3.0-or-later`); see [`LICENSE`](LICENSE). Every source file carries
an `SPDX-License-Identifier: GPL-3.0-or-later` header.

It reuses protocol lessons from
[openfortivpn](https://github.com/adrienverge/openfortivpn) (© Adrien Vergé and
contributors, GPLv3) — credit for the FortiGate protocol logic goes to that
project.

**OpenSSL linking exception.** As an additional permission under section 7 of the
GPL v3, the CrossWire copyright holders permit linking this program with the
OpenSSL library and distributing the result; you must still comply with the GPL
v3 for all code other than OpenSSL. OpenSSL's own license is reproduced in
[`LICENSE.OpenSSL`](LICENSE.OpenSSL). (OpenSSL ≥ 3.0 is Apache-2.0, already
GPLv3-compatible; the exception covers older releases.)

**Dependencies.** All Rust crate dependencies are under permissive,
GPLv3-compatible licenses (MIT, Apache-2.0, BSD, Zlib, …), each retaining its own
license.
