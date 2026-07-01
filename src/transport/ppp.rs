// SPDX-License-Identifier: GPL-3.0-or-later
//! ppp process management.
//!
//! Spawns the platform PPP daemon on a pty via `forkpty` — `pppd` on Linux,
//! `ppp -direct` on BSD/macOS — and returns a [`PppdGuard`] that terminates and
//! reaps the child on drop, plus the pty master fd for the io-loop to drive.

use crate::cli::Config;
use crate::core::provider::TunnelParams;
use anyhow::{Result, bail};
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::ffi::CString;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

/// How long to wait for a graceful SIGTERM exit before escalating to SIGKILL.
const GRACEFUL_KILL_TIMEOUT: Duration = Duration::from_secs(2);
const GRACEFUL_KILL_STEP: Duration = Duration::from_millis(100);

/// Owns the pppd child; on drop it sends SIGTERM and reaps.
pub struct PppdGuard {
    child: Pid,
    reaped: bool,
}

impl PppdGuard {
    /// Terminate and reap the child. Idempotent. Sends SIGTERM, waits briefly
    /// for a graceful exit, then escalates to SIGKILL so teardown can never hang
    /// on a pppd that ignores SIGTERM.
    pub fn reap(&mut self) -> Option<i32> {
        if self.reaped {
            return None;
        }
        self.reaped = true;
        let _ = kill(self.child, Signal::SIGTERM);

        // Poll for a graceful exit until a wall-clock deadline. `EINTR` (e.g. a
        // SIGCHLD from another child) is expected during teardown and retried;
        // using a deadline keeps the grace period correct regardless.
        let deadline = Instant::now() + GRACEFUL_KILL_TIMEOUT;
        loop {
            match waitpid(self.child, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(GRACEFUL_KILL_STEP);
                }
                Ok(status) => return report_status(status),
                Err(Errno::EINTR) => continue,
                Err(e) => {
                    tracing::debug!("waitpid(pppd) failed: {}", e);
                    return None;
                }
            }
        }

        // Still alive after the grace period: force-kill and reap.
        tracing::warn!("pppd did not exit on SIGTERM; sending SIGKILL");
        let _ = kill(self.child, Signal::SIGKILL);
        loop {
            match waitpid(self.child, None) {
                Ok(status) => return report_status(status),
                Err(Errno::EINTR) => continue,
                Err(e) => {
                    tracing::debug!("waitpid(pppd) after SIGKILL failed: {}", e);
                    return None;
                }
            }
        }
    }
}

fn report_status(status: WaitStatus) -> Option<i32> {
    match status {
        WaitStatus::Exited(_, code) => {
            tracing::info!("pppd exited: {}", ppp_exit_message(code));
            Some(code)
        }
        WaitStatus::Signaled(_, sig, _) => {
            tracing::info!("pppd killed by signal {:?}", sig);
            None
        }
        _ => None,
    }
}

impl Drop for PppdGuard {
    fn drop(&mut self) {
        self.reap();
    }
}

/// A subset of pppd's exit-code table (see pppd(8)).
fn ppp_exit_message(code: i32) -> String {
    let msg = match code {
        0 => "OK",
        1 => "fatal error",
        2 => "options error",
        5 => "terminated by signal",
        8 => "peer refused authentication",
        15 => "peer not responding",
        16 => "link terminated by modem hangup",
        19 => "authentication failed",
        _ => "see pppd(8) for exit code",
    };
    format!("code {} ({})", code, msg)
}

/// Spawn pppd on a fresh pty. Returns the reaping guard and the pty master fd
/// (owned, so it is always closed on drop — even if the io task never runs).
pub fn spawn_pppd(
    config: &Config,
    ifname: &str,
    params: &TunnelParams,
) -> Result<(PppdGuard, OwnedFd)> {
    use nix::pty::{ForkptyResult, forkpty};
    use nix::unistd::execve;

    // Build argv + environment in the parent so the post-fork child only execs.
    // The env carries the split-tunnel routes and DNS to a pppd plugin (e.g. the
    // NetworkManager one), which can't otherwise learn them — they come from the
    // gateway's config response, not PPP.
    let argv = ppp_argv(config, ifname);
    let envp = pppd_envp(params);

    match unsafe { forkpty(None, None) } {
        Ok(ForkptyResult::Parent { child, master }) => {
            tracing::debug!("ppp daemon spawned with PID {}", child);
            Ok((
                PppdGuard {
                    child,
                    reaped: false,
                },
                master,
            ))
        }
        Ok(ForkptyResult::Child) => {
            let _ = execve(argv[0].as_c_str(), &argv, &envp);
            // Only reached if execve failed.
            std::process::exit(1);
        }
        Err(e) => bail!("forkpty failed: {}", e),
    }
}

/// The child's environment: our own env plus the network parameters a pppd
/// plugin can't learn from PPP (they come from the gateway's config response):
///   CROSSWIRE_ROUTES      comma-separated `dest/prefix` (empty = full-tunnel)
///   CROSSWIRE_DNS         comma-separated DNS server IPs
///   CROSSWIRE_DNS_SUFFIX  search domain (only if the gateway sent one)
fn pppd_envp(params: &TunnelParams) -> Vec<CString> {
    let mut envp: Vec<CString> = std::env::vars_os()
        .filter_map(|(k, v)| {
            let mut s = k.into_string().ok()?;
            s.push('=');
            s.push_str(&v.into_string().ok()?);
            CString::new(s).ok()
        })
        .collect();

    let join = |v: &[String]| v.join(",");
    let routes = params
        .routes
        .iter()
        .map(|r| format!("{}/{}", r.dest, r.prefix))
        .collect::<Vec<_>>();
    let dns = params.dns.iter().map(|d| d.to_string()).collect::<Vec<_>>();

    envp.push(cs(&format!("CROSSWIRE_ROUTES={}", join(&routes))));
    envp.push(cs(&format!("CROSSWIRE_DNS={}", join(&dns))));
    if let Some(sfx) = &params.dns_suffix {
        envp.push(cs(&format!("CROSSWIRE_DNS_SUFFIX={sfx}")));
    }
    envp
}

/// The platform PPP argument vector (argv[0] is the program path).
fn ppp_argv(config: &Config, ifname: &str) -> Vec<CString> {
    #[cfg(target_os = "linux")]
    {
        linux_pppd_argv(config, ifname)
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        bsd_ppp_argv(config, ifname)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        let _ = (config, ifname);
        vec![CString::new("/bin/false").unwrap()]
    }
}

fn cs(s: &str) -> CString {
    CString::new(s).expect("nul byte in ppp argument")
}

/// Linux `pppd` argument vector.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_pppd_argv(config: &Config, ifname: &str) -> Vec<CString> {
    let mut args = vec![
        cs("/usr/sbin/pppd"),
        cs("230400"),
        cs(":169.254.2.1"),
        cs("noipdefault"),
        cs("ipcp-accept-local"),
        cs("noaccomp"),
        cs("noauth"),
        cs("default-asyncmap"),
        cs("nopcomp"),
        cs("receive-all"),
        cs("nodefaultroute"),
        cs("nodetach"),
        cs("lcp-max-configure"),
        cs("40"),
        cs("mru"),
        cs("1354"),
        cs("ifname"),
        cs(ifname),
    ];

    if config.pppd_use_peerdns {
        args.push(cs("usepeerdns"));
    }

    if let Some(log) = &config.pppd_log
        && let Some(path) = log.to_str()
    {
        args.push(cs("debug"));
        args.push(cs("logfile"));
        args.push(cs(path));
    } else {
        // pppd defaults to logging on fd 1, which would clobber PPP data.
        args.push(cs("logfd"));
        args.push(cs("2"));
    }

    if let Some(plugin) = &config.pppd_plugin
        && let Some(path) = plugin.to_str()
    {
        args.push(cs("plugin"));
        args.push(cs(path));
    }

    if let Some(ipparam) = &config.pppd_ipparam {
        args.push(cs("ipparam"));
        args.push(cs(ipparam));
    }

    if let Some(system) = &config.pppd_system {
        args.push(cs("system"));
        args.push(cs(system));
    }

    args
}

/// BSD/macOS `ppp -direct <label>` argument vector. The label is a profile in
/// `/etc/ppp/ppp.conf`; upstream uses the configured system name.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn bsd_ppp_argv(config: &Config, ifname: &str) -> Vec<CString> {
    let label = config.pppd_system.as_deref().unwrap_or(ifname);
    vec![cs("/usr/sbin/ppp"), cs("-direct"), cs(label)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv_strings(v: &[CString]) -> Vec<String> {
        v.iter().map(|c| c.to_string_lossy().into_owned()).collect()
    }

    /// Producer side of the CROSSWIRE_* env contract with the NetworkManager
    /// pppd plugin (see crosswire-network-manager/pppd-plugin/
    /// CROSSWIRE_ENV_CONTRACT.md). This fixture must match the plugin's
    /// test-netparams golden strings.
    #[test]
    fn pppd_envp_encodes_routes_dns_suffix() {
        use crate::core::provider::{Route, TunnelParams};

        let params = TunnelParams {
            dns: vec![
                "172.31.13.10".parse().unwrap(),
                "172.31.13.11".parse().unwrap(),
            ],
            dns_suffix: Some("corp.local".into()),
            routes: vec![
                Route {
                    dest: "10.0.0.0".parse().unwrap(),
                    prefix: 8,
                },
                Route {
                    dest: "172.16.0.0".parse().unwrap(),
                    prefix: 12,
                },
                Route {
                    dest: "192.168.1.0".parse().unwrap(),
                    prefix: 24,
                },
            ],
            ..Default::default()
        };

        let envp = pppd_envp(&params);
        let val = |key: &str| {
            envp.iter()
                .filter_map(|c| c.to_str().ok())
                .find_map(|s| s.strip_prefix(key))
        };

        assert_eq!(
            val("CROSSWIRE_ROUTES="),
            Some("10.0.0.0/8,172.16.0.0/12,192.168.1.0/24")
        );
        assert_eq!(val("CROSSWIRE_DNS="), Some("172.31.13.10,172.31.13.11"));
        assert_eq!(val("CROSSWIRE_DNS_SUFFIX="), Some("corp.local"));
        // Our own environment is preserved (PATH almost always present).
        assert!(
            envp.iter()
                .filter_map(|c| c.to_str().ok())
                .any(|s| s.starts_with("PATH="))
        );
    }

    /// Full-tunnel: empty routes/DNS still emit the (empty) vars; no suffix.
    #[test]
    fn pppd_envp_full_tunnel_is_empty() {
        use crate::core::provider::TunnelParams;
        let envp = pppd_envp(&TunnelParams::default());
        let val = |key: &str| {
            envp.iter()
                .filter_map(|c| c.to_str().ok())
                .find_map(|s| s.strip_prefix(key))
        };
        assert_eq!(val("CROSSWIRE_ROUTES="), Some(""));
        assert_eq!(val("CROSSWIRE_DNS="), Some(""));
        assert_eq!(val("CROSSWIRE_DNS_SUFFIX="), None);
    }

    #[test]
    fn linux_argv_has_core_options() {
        let cfg = Config {
            pppd_use_peerdns: true,
            ..Default::default()
        };
        let argv = argv_strings(&linux_pppd_argv(&cfg, "ppp0"));
        assert_eq!(argv[0], "/usr/sbin/pppd");
        assert!(argv.contains(&"nodetach".to_string()));
        assert!(argv.contains(&"usepeerdns".to_string()));
        // ifname is passed through.
        let i = argv.iter().position(|a| a == "ifname").unwrap();
        assert_eq!(argv[i + 1], "ppp0");
    }

    #[test]
    fn bsd_argv_uses_ppp_direct() {
        let cfg = Config {
            pppd_system: Some("myvpn".into()),
            ..Default::default()
        };
        let argv = argv_strings(&bsd_ppp_argv(&cfg, "ppp0"));
        assert_eq!(argv, vec!["/usr/sbin/ppp", "-direct", "myvpn"]);

        // Falls back to the interface name when no system label is set.
        let argv2 = argv_strings(&bsd_ppp_argv(&Config::default(), "tun0"));
        assert_eq!(argv2, vec!["/usr/sbin/ppp", "-direct", "tun0"]);
    }

    // The reap tests fork real children; the child branches use only
    // async-signal-safe libc calls and never return into the test harness.

    #[test]
    fn reap_handles_graceful_child() {
        use nix::unistd::{ForkResult, fork};
        use std::time::Instant;

        match unsafe { fork() }.unwrap() {
            ForkResult::Child => {
                // Default SIGTERM disposition terminates us during pause().
                unsafe {
                    libc::pause();
                    libc::_exit(0);
                }
            }
            ForkResult::Parent { child } => {
                let mut guard = PppdGuard {
                    child,
                    reaped: false,
                };
                let start = Instant::now();
                guard.reap();
                assert!(
                    start.elapsed() < Duration::from_secs(1),
                    "a child that honors SIGTERM should reap quickly"
                );
            }
        }
    }

    #[test]
    fn reap_force_kills_stuck_child() {
        use nix::unistd::{ForkResult, fork};
        use std::time::Instant;

        match unsafe { fork() }.unwrap() {
            ForkResult::Child => unsafe {
                // Ignore SIGTERM, then block forever until SIGKILL.
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
                loop {
                    libc::pause();
                }
            },
            ForkResult::Parent { child } => {
                // Let the child install its SIGTERM-ignoring handler first.
                std::thread::sleep(Duration::from_millis(300));
                let mut guard = PppdGuard {
                    child,
                    reaped: false,
                };
                let start = Instant::now();
                guard.reap();
                let elapsed = start.elapsed();
                assert!(
                    elapsed >= Duration::from_millis(1900),
                    "should wait the grace period before escalating to SIGKILL"
                );
                assert!(
                    elapsed < Duration::from_secs(5),
                    "teardown must never hang on a stuck child"
                );
                // The child has been reaped: no waitable child remains.
                assert!(waitpid(child, Some(WaitPidFlag::WNOHANG)).is_err());
            }
        }
    }
}
