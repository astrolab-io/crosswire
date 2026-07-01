// SPDX-License-Identifier: GPL-3.0-or-later
//! BSD/macOS network configurator (`route` / `netstat` / `ifconfig`).
//!
//! Mirrors the structure of [`crate::net::linux`] but uses the BSD tools.
//! Addressing is left to the `ppp` daemon (which negotiates it via IPCP on
//! BSD), so this backend configures routes and DNS. It shells out with portable
//! `std::process::Command`, so the module compiles (and its parser tests run) on
//! every platform; it is only *selected* on BSD-family targets.
#![cfg_attr(
    not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )),
    allow(dead_code)
)]

use crate::cli::Config;
use crate::core::provider::TunnelParams;
use crate::net::{AppliedNetwork, NetworkConfigurator};
use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Duration;

const RESOLV_CONF: &str = "/etc/resolv.conf";

pub struct BsdNet;

impl NetworkConfigurator for BsdNet {
    fn apply(
        &self,
        params: &TunnelParams,
        ifname: &str,
        config: &Config,
    ) -> Result<AppliedNetwork> {
        let mut applied = AppliedNetwork::new();

        // Address assignment is handled by the ppp daemon (IPCP) on BSD.
        if params.assigned_addr.is_some() {
            tracing::debug!("BSD: leaving interface address assignment to the ppp daemon");
        }

        if config.set_routes {
            if params.routes.is_empty() {
                apply_full_tunnel(&mut applied, ifname, config)?;
            } else {
                for r in &params.routes {
                    let cidr = format!("{}/{}", r.dest, r.prefix);
                    match run_route(&["-n", "add", "-net", &cidr, "-interface", ifname]) {
                        Ok(()) => {
                            tracing::info!("Added route {} dev {}", cidr, ifname);
                            let cidr_owned = cidr.clone();
                            applied.push_cleanup(move || {
                                let _ = run_route(&["-n", "delete", "-net", &cidr_owned]);
                            });
                        }
                        Err(e) => tracing::warn!("Failed to add route {}: {}", cidr, e),
                    }
                }
            }
        }

        if config.set_dns && !config.pppd_use_peerdns && !params.dns.is_empty() {
            apply_dns_file(&mut applied, params)?;
        }

        Ok(applied)
    }
}

fn apply_full_tunnel(applied: &mut AppliedNetwork, ifname: &str, config: &Config) -> Result<()> {
    let default = read_default_route();

    // Protect the gateway route via the pre-existing default gateway.
    match (&default, resolve_gateway_ip(config)) {
        (Some((old_gw, _)), Some(gw_ip)) => {
            let host = gw_ip.to_string();
            match run_route(&["-n", "add", "-host", &host, old_gw]) {
                Ok(()) => {
                    tracing::info!("Protected gateway route {} via {}", host, old_gw);
                    let host2 = host.clone();
                    applied.push_cleanup(move || {
                        let _ = run_route(&["-n", "delete", "-host", &host2]);
                    });
                }
                Err(e) => tracing::warn!("Failed to protect gateway route {}: {}", host, e),
            }
        }
        (None, _) => tracing::warn!("No existing default route; gateway-route protection skipped"),
        (_, None) => tracing::warn!("Could not resolve VPN gateway IP; protection skipped"),
    }

    if config.half_internet_routes {
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            if run_route(&["-n", "add", "-net", half, "-interface", ifname]).is_ok() {
                let h = half.to_string();
                applied.push_cleanup(move || {
                    let _ = run_route(&["-n", "delete", "-net", &h]);
                });
            }
        }
        tracing::info!("Full-tunnel via half-internet routes on {}", ifname);
    } else {
        let _ = run_route(&["-n", "delete", "default"]);
        run_route(&["-n", "add", "default", "-interface", ifname])
            .context("redirecting default route through the tunnel")?;
        tracing::info!("Default route redirected via {}", ifname);
        if let Some((old_gw, _)) = default {
            applied.push_cleanup(move || {
                let _ = run_route(&["-n", "delete", "default"]);
                let _ = run_route(&["-n", "add", "default", &old_gw]);
            });
        }
    }
    Ok(())
}

fn apply_dns_file(applied: &mut AppliedNetwork, params: &TunnelParams) -> Result<()> {
    let original = std::fs::read(RESOLV_CONF).unwrap_or_default();
    let mut new = String::new();
    if let Some(sfx) = &params.dns_suffix {
        new.push_str(&format!("search {}\n", sfx));
    }
    for d in &params.dns {
        new.push_str(&format!("nameserver {}\n", d));
    }
    new.push_str(&String::from_utf8_lossy(&original));
    std::fs::write(RESOLV_CONF, new.as_bytes()).context("writing /etc/resolv.conf")?;
    applied.push_cleanup(move || {
        let _ = std::fs::write(RESOLV_CONF, &original);
    });
    Ok(())
}

/// Wait (bounded) for the ppp interface to come up (parses `ifconfig <if>`).
pub async fn wait_for_iface(ifname: &str, timeout: Duration) -> Result<()> {
    let iterations = (timeout.as_millis() / 500).max(1);
    for _ in 0..iterations {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Ok(out) = Command::new("ifconfig").arg(ifname).output()
            && out.status.success()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            // Up and carrying an inet address.
            if s.contains("inet ") && (s.contains("RUNNING") || s.contains("UP")) {
                tracing::info!("Interface {} is up", ifname);
                return Ok(());
            }
        }
        tracing::debug!("Waiting for interface {} to come up...", ifname);
    }
    anyhow::bail!("interface {} did not come up within {:?}", ifname, timeout)
}

fn resolve_gateway_ip(config: &Config) -> Option<Ipv4Addr> {
    use std::net::ToSocketAddrs;
    (config.host.as_str(), config.port)
        .to_socket_addrs()
        .ok()?
        .find_map(|sa| match sa.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
}

/// Read the current IPv4 default route (gateway, iface) via `netstat -rn`.
fn read_default_route() -> Option<(String, String)> {
    let out = Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_default_gateway(&String::from_utf8_lossy(&out.stdout))
}

/// Parse `netstat -rn` output for the default route's (gateway, iface).
fn parse_default_gateway(output: &str) -> Option<(String, String)> {
    for line in output.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.first() == Some(&"default") && f.len() >= 4 {
            let gateway = f[1].to_string();
            // The interface is the Netif column (last non-Expire field). Take the
            // first later field that looks like an interface name.
            let iface = f[2..]
                .iter()
                .find(|s| s.chars().any(|c| c.is_ascii_digit()) && !s.contains('.'))
                .unwrap_or(&f[f.len() - 1])
                .to_string();
            return Some((gateway, iface));
        }
    }
    None
}

fn run_route(args: &[&str]) -> Result<()> {
    let out = Command::new("route")
        .args(args)
        .output()
        .context("failed to run route")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("route {:?} failed: {}", args, err.trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_default_gateway() {
        // macOS `netstat -rn` layout.
        let output = "\
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGSc          en0
127                127.0.0.1          UCS           lo0
";
        let (gw, iface) = parse_default_gateway(output).unwrap();
        assert_eq!(gw, "192.168.1.1");
        assert_eq!(iface, "en0");
    }

    #[test]
    fn parses_freebsd_default_gateway() {
        let output = "Routing tables

Internet:
Destination        Gateway            Flags     Netif Expire
default            10.0.0.1           UGS         em0
10.0.0.0/24        link#1             U           em0
";
        let (gw, iface) = parse_default_gateway(output).unwrap();
        assert_eq!(gw, "10.0.0.1");
        assert_eq!(iface, "em0");
    }

    #[test]
    fn no_default_when_absent() {
        let output = "Internet:\nDestination Gateway Flags Netif\n127 127.0.0.1 UCS lo0\n";
        assert!(parse_default_gateway(output).is_none());
    }
}
