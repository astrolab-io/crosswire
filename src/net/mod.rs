// SPDX-License-Identifier: GPL-3.0-or-later
//! Network configuration abstraction.
//!
//! A [`NetworkConfigurator`] applies the tunnel's addressing/routing/DNS to the
//! system and returns an [`AppliedNetwork`] whose `Drop` restores the previous
//! state. This keeps teardown automatic on every exit path.

// Both backends use only portable Rust (Command + fs), so they compile on every
// platform for full type-checking and unit tests; only *selection* is
// platform-gated below.
pub mod browser;
pub mod bsd;
pub mod linux;

use crate::cli::Config;
use crate::core::provider::TunnelParams;
use anyhow::Result;
use std::time::Duration;

/// The network configurator for the current platform. BSD family = macos,
/// freebsd, openbsd, netbsd, dragonfly.
pub fn configurator() -> Box<dyn NetworkConfigurator> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxNet)
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        Box::new(bsd::BsdNet)
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
        Box::new(UnsupportedNet)
    }
}

/// Wait (bounded) for the pppd interface to come up. Platform-dispatched.
pub async fn wait_for_iface(ifname: &str, timeout: Duration) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::wait_for_iface(ifname, timeout).await
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        bsd::wait_for_iface(ifname, timeout).await
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
        let _ = (ifname, timeout);
        anyhow::bail!("interface bring-up detection is not implemented on this platform")
    }
}

/// Fallback configurator for platforms without a network backend yet.
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
pub struct UnsupportedNet;

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
impl NetworkConfigurator for UnsupportedNet {
    fn apply(&self, _: &TunnelParams, _: &str, _: &Config) -> Result<AppliedNetwork> {
        anyhow::bail!(
            "no network backend for this platform yet; run with --set-routes false --set-dns false \
             to skip, or add a NetworkConfigurator impl (see net::linux)"
        )
    }
}

/// Records undo actions applied to the system; runs them (in reverse) on drop.
#[derive(Default)]
pub struct AppliedNetwork {
    cleanups: Vec<Box<dyn FnMut() + Send>>,
}

impl AppliedNetwork {
    pub fn new() -> Self {
        Self {
            cleanups: Vec::new(),
        }
    }

    /// Register a cleanup to run on teardown.
    pub fn push_cleanup<F: FnMut() + Send + 'static>(&mut self, f: F) {
        self.cleanups.push(Box::new(f));
    }
}

impl Drop for AppliedNetwork {
    fn drop(&mut self) {
        // Restore in reverse order of application.
        while let Some(mut c) = self.cleanups.pop() {
            c();
        }
    }
}

/// Applies tunnel network parameters to the system.
pub trait NetworkConfigurator: Send + Sync {
    /// Apply addressing, routes and DNS for `ifname`, returning restore guards.
    fn apply(&self, params: &TunnelParams, ifname: &str, config: &Config)
    -> Result<AppliedNetwork>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::provider::TunnelParams;
    use std::sync::{Arc, Mutex};

    #[test]
    fn cleanups_run_in_reverse_on_drop() {
        let log = Arc::new(Mutex::new(Vec::new()));
        {
            let mut applied = AppliedNetwork::new();
            for i in 0..3 {
                let log = log.clone();
                applied.push_cleanup(move || log.lock().unwrap().push(i));
            }
        }
        assert_eq!(*log.lock().unwrap(), vec![2, 1, 0]);
    }

    struct MockConfigurator {
        log: Arc<Mutex<Vec<String>>>,
    }

    impl NetworkConfigurator for MockConfigurator {
        fn apply(
            &self,
            params: &TunnelParams,
            ifname: &str,
            _config: &Config,
        ) -> Result<AppliedNetwork> {
            self.log
                .lock()
                .unwrap()
                .push(format!("apply:{}:dns={}", ifname, params.dns.len()));
            let mut net = AppliedNetwork::new();
            let log = self.log.clone();
            let ifn = ifname.to_string();
            net.push_cleanup(move || log.lock().unwrap().push(format!("restore:{}", ifn)));
            Ok(net)
        }
    }

    #[test]
    fn configurator_applies_then_restores_on_drop() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let config = Config::default();
        let params = TunnelParams::default();
        let m = MockConfigurator { log: log.clone() };
        {
            let _applied = m.apply(&params, "ppp0", &config).unwrap();
            assert_eq!(log.lock().unwrap().len(), 1, "restore must not run early");
        }
        let l = log.lock().unwrap();
        assert_eq!(l[0], "apply:ppp0:dns=0");
        assert_eq!(l[1], "restore:ppp0");
    }
}
