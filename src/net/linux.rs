// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux network configurator.
//!
//! Routes/addresses are applied via the `ip` command; DNS via an auto-detected
//! backend (`resolvectl`, `resolvconf`, or direct `/etc/resolv.conf` edit with
//! backup+restore). Every applied change registers an undo action on the
//! returned [`AppliedNetwork`].
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::cli::Config;
use crate::core::provider::TunnelParams;
use crate::net::{AppliedNetwork, NetworkConfigurator};
use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const RESOLV_CONF: &str = "/etc/resolv.conf";

pub struct LinuxNet;

impl NetworkConfigurator for LinuxNet {
    fn apply(
        &self,
        params: &TunnelParams,
        ifname: &str,
        config: &Config,
    ) -> Result<AppliedNetwork> {
        let mut applied = AppliedNetwork::new();

        // 1. Assigned address (point-to-point /32). Skipped when --set-ip=false
        // so an external manager (pppd/NetworkManager) can own the address.
        if let (true, Some(addr)) = (config.set_ip, params.assigned_addr) {
            let cidr = format!("{}/32", addr);
            run_ip(&["addr", "add", &cidr, "dev", ifname])
                .with_context(|| format!("adding address {}", cidr))?;
            let ifname_owned = ifname.to_string();
            applied.push_cleanup(move || {
                let _ = run_ip(&["addr", "del", &cidr, "dev", &ifname_owned]);
            });
        }

        // 2. Routes.
        if config.set_routes {
            if params.routes.is_empty() {
                apply_full_tunnel(&mut applied, ifname, config)?;
            } else {
                for r in &params.routes {
                    let cidr = format!("{}/{}", r.dest, r.prefix);
                    match run_ip(&["route", "add", &cidr, "dev", ifname]) {
                        Ok(()) => {
                            tracing::info!("Added route {} dev {}", cidr, ifname);
                            let ifname_owned = ifname.to_string();
                            let cidr_owned = cidr.clone();
                            applied.push_cleanup(move || {
                                let _ =
                                    run_ip(&["route", "del", &cidr_owned, "dev", &ifname_owned]);
                            });
                        }
                        Err(e) => tracing::warn!("Failed to add route {}: {}", cidr, e),
                    }
                }
            }
        }

        // 3. DNS.
        if config.set_dns && !config.pppd_use_peerdns && !params.dns.is_empty() {
            apply_dns(&mut applied, params, ifname, config)?;
        }

        Ok(applied)
    }
}

/// Full-tunnel mode: protect the route to the VPN gateway, then redirect the
/// default route (or add the two half-internet routes) through the tunnel.
fn apply_full_tunnel(applied: &mut AppliedNetwork, ifname: &str, config: &Config) -> Result<()> {
    let default = read_default_route();

    // Protect the gateway route: keep encrypted traffic to the gateway flowing
    // through the *old* default gateway once we redirect the default route.
    match (&default, resolve_gateway_ip(config)) {
        (Some((old_gw, old_iface)), Some(gw_ip)) => {
            let gw_cidr = format!("{}/32", gw_ip);
            let via = old_gw.to_string();
            match run_ip(&["route", "add", &gw_cidr, "via", &via, "dev", old_iface]) {
                Ok(()) => {
                    tracing::info!("Protected gateway route {} via {}", gw_cidr, via);
                    let gw_cidr2 = gw_cidr.clone();
                    applied.push_cleanup(move || {
                        let _ = run_ip(&["route", "del", &gw_cidr2]);
                    });
                }
                Err(e) => tracing::warn!("Failed to protect gateway route {}: {}", gw_cidr, e),
            }
        }
        (None, _) => tracing::warn!("No existing default route; gateway-route protection skipped"),
        (_, None) => tracing::warn!("Could not resolve VPN gateway IP; protection skipped"),
    }

    if config.half_internet_routes {
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            if run_ip(&["route", "add", half, "dev", ifname]).is_ok() {
                let h = half.to_string();
                let ifn = ifname.to_string();
                applied.push_cleanup(move || {
                    let _ = run_ip(&["route", "del", &h, "dev", &ifn]);
                });
            }
        }
        tracing::info!("Full-tunnel via half-internet routes on {}", ifname);
    } else {
        run_ip(&["route", "replace", "default", "dev", ifname])
            .context("redirecting default route through the tunnel")?;
        tracing::info!("Default route redirected via {}", ifname);
        match default {
            Some((old_gw, old_iface)) => {
                let via = old_gw.to_string();
                applied.push_cleanup(move || {
                    let _ = run_ip(&[
                        "route", "replace", "default", "via", &via, "dev", &old_iface,
                    ]);
                });
            }
            None => applied.push_cleanup(|| {
                let _ = run_ip(&["route", "del", "default"]);
            }),
        }
    }
    Ok(())
}

/// Resolve the VPN gateway host to its first IPv4 address.
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

/// Read the current IPv4 default route (gateway, iface) from `/proc/net/route`.
fn read_default_route() -> Option<(Ipv4Addr, String)> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_default_route(&content)
}

/// Parse `/proc/net/route` content for the default route. Addresses are stored
/// as little-endian hex; flags bit 0x2 (RTF_GATEWAY) and a `00000000`
/// destination identify the default route.
fn parse_default_route(content: &str) -> Option<(Ipv4Addr, String)> {
    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let (iface, dest, gateway, flags) = (f[0], f[1], f[2], f[3]);
        let flags = u32::from_str_radix(flags, 16).unwrap_or(0);
        if dest.eq_ignore_ascii_case("00000000")
            && flags & 0x2 != 0
            && let Ok(gw) = u32::from_str_radix(gateway, 16)
        {
            return Some((Ipv4Addr::from(gw.to_le_bytes()), iface.to_string()));
        }
    }
    None
}

fn apply_dns(
    applied: &mut AppliedNetwork,
    params: &TunnelParams,
    ifname: &str,
    config: &Config,
) -> Result<()> {
    let backend = DnsBackend::detect(config);
    tracing::info!("Configuring DNS via {:?} backend", backend);
    match backend {
        DnsBackend::Resolvectl => {
            let mut args: Vec<String> = vec!["dns".into(), ifname.into()];
            args.extend(params.dns.iter().map(|d| d.to_string()));
            run_cmd("resolvectl", &to_str_vec(&args))?;
            if let Some(sfx) = &params.dns_suffix {
                let _ = run_cmd("resolvectl", &["domain", ifname, sfx]);
            }
            let ifname_owned = ifname.to_string();
            applied.push_cleanup(move || {
                let _ = run_cmd("resolvectl", &["revert", &ifname_owned]);
            });
        }
        DnsBackend::Resolvconf => {
            let stanza = render_resolv(&params.dns, params.dns_suffix.as_deref());
            run_cmd_stdin("resolvconf", &["-a", ifname], &stanza)?;
            let ifname_owned = ifname.to_string();
            applied.push_cleanup(move || {
                let _ = run_cmd("resolvconf", &["-d", &ifname_owned]);
            });
        }
        DnsBackend::File => {
            let original = std::fs::read(RESOLV_CONF).unwrap_or_default();
            let mut new = render_resolv(&params.dns, params.dns_suffix.as_deref());
            new.push_str(&String::from_utf8_lossy(&original));
            std::fs::write(RESOLV_CONF, new.as_bytes()).context("writing /etc/resolv.conf")?;
            applied.push_cleanup(move || {
                let _ = std::fs::write(RESOLV_CONF, &original);
            });
        }
    }
    Ok(())
}

fn render_resolv(dns: &[Ipv4Addr], suffix: Option<&str>) -> String {
    let mut s = String::new();
    if let Some(sfx) = suffix {
        s.push_str(&format!("search {}\n", sfx));
    }
    for d in dns {
        s.push_str(&format!("nameserver {}\n", d));
    }
    s
}

#[derive(Debug, Clone, Copy)]
enum DnsBackend {
    Resolvectl,
    Resolvconf,
    File,
}

impl DnsBackend {
    fn detect(config: &Config) -> Self {
        if config.use_resolvconf && command_exists("resolvconf") {
            return DnsBackend::Resolvconf;
        }
        if command_exists("resolvectl") {
            DnsBackend::Resolvectl
        } else if command_exists("resolvconf") {
            DnsBackend::Resolvconf
        } else {
            DnsBackend::File
        }
    }
}

/// Wait (bounded) for the pppd interface to come up with an address.
pub async fn wait_for_iface(ifname: &str, timeout: Duration) -> Result<()> {
    let deadline = timeout.as_millis() / 500;
    for _ in 0..deadline.max(1) {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Ok(out) = Command::new("ip").args(["link", "show", ifname]).output()
            && out.status.success()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.contains("state UP")
                || (s.contains("state UNKNOWN") && s.contains("UP") && s.contains("LOWER_UP"))
            {
                tracing::info!("Interface {} is up", ifname);
                return Ok(());
            }
        }
        tracing::debug!("Waiting for interface {} to come up...", ifname);
    }
    anyhow::bail!("interface {} did not come up within {:?}", ifname, timeout)
}

fn run_ip(args: &[&str]) -> Result<()> {
    run_cmd("ip", args)
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {}", cmd))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("{} {:?} failed: {}", cmd, args, err.trim());
    }
    Ok(())
}

fn run_cmd_stdin(cmd: &str, args: &[&str], stdin: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {}", cmd))?;
    child
        .stdin
        .take()
        .context("no stdin")?
        .write_all(stdin.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("{} {:?} failed", cmd, args);
    }
    Ok(())
}

fn to_str_vec(v: &[String]) -> Vec<&str> {
    v.iter().map(|s| s.as_str()).collect()
}

/// Check whether `name` is an executable somewhere on `$PATH`.
fn command_exists(name: &str) -> bool {
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            if Path::new(dir).join(name).is_file() {
                return true;
            }
        }
    }
    // Fallback to common sbin locations not always in PATH.
    ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .iter()
        .any(|d| Path::new(d).join(name).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_route() {
        // Real /proc/net/route layout. Gateway 0102A8C0 (LE) = 192.168.2.1,
        // dest 00000000, flags 0003 (UP|GATEWAY) on eth0. The second line is a
        // non-default on-link route that must be ignored.
        let content = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";
        let (gw, iface) = parse_default_route(content).unwrap();
        assert_eq!(gw, Ipv4Addr::new(192, 168, 2, 1));
        assert_eq!(iface, "eth0");
    }

    #[test]
    fn no_default_route_when_absent() {
        let content =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";
        assert!(parse_default_route(content).is_none());
    }
}
