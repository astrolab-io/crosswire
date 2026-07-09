// SPDX-License-Identifier: GPL-3.0-or-later
//! Live connection-progress reporting.
//!
//! The engine reports each phase of bringing the tunnel up through a [`Progress`]
//! handle. When a SAML login opens the browser, the local callback page keeps
//! itself open and subscribes to these updates over SSE, so the user watches the
//! connection come up (and sees a clear success/error badge) instead of a page
//! that closes the instant sign-in completes. For non-browser auth it's inert.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;

/// A phase of the connection lifecycle, surfaced to the browser status page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Signed in via SAML; exchanging the assertion for a session cookie.
    Authenticating,
    /// Authenticated; about to fetch the tunnel parameters.
    Authenticated,
    /// Fetching the VPN network configuration (address, routes, DNS).
    FetchingConfig,
    /// Bringing up pppd and opening the encrypted tunnel.
    StartingTunnel,
    /// Applying the negotiated address, routes, and DNS.
    ConfiguringNetwork,
    /// The tunnel is fully up.
    Up,
    /// The connection attempt failed; carries a one-line reason.
    Failed(String),
}

impl Status {
    /// `(kind, message)` for the status page. `kind` is one of `loading`,
    /// `success`, `error` — matching the SSE event names the page listens for.
    pub fn render(&self) -> (&'static str, String) {
        match self {
            Status::Authenticating => ("loading", "Completing sign-in…".into()),
            Status::Authenticated => ("loading", "Signed in. Preparing connection…".into()),
            Status::FetchingConfig => ("loading", "Fetching VPN configuration…".into()),
            Status::StartingTunnel => ("loading", "Establishing secure tunnel…".into()),
            Status::ConfiguringNetwork => ("loading", "Configuring routes and DNS…".into()),
            Status::Up => ("success", "Connected. You're all set.".into()),
            // Collapse whitespace so it stays a single SSE `data:` line.
            Status::Failed(e) => ("error", format!("Connection failed: {}", one_line(e))),
        }
    }

    /// A terminal status: the page shows a badge and closes shortly after.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Status::Up | Status::Failed(_))
    }
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A cheap-to-clone handle for publishing [`Status`] updates. Backed by a
/// `watch` channel so a late subscriber (the browser page, which connects only
/// after sign-in) immediately sees the current phase and every one after it.
#[derive(Clone)]
pub struct Progress {
    tx: Arc<watch::Sender<Status>>,
    /// Set once the SAML callback page has loaded, so the engine knows a browser
    /// is watching and grants it a moment to render a terminal state before exit.
    browser_open: Arc<AtomicBool>,
}

impl Progress {
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(Status::Authenticating);
        Self {
            tx: Arc::new(tx),
            browser_open: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Publish the current connection phase.
    pub fn report(&self, status: Status) {
        tracing::debug!("progress: {:?}", status);
        // `send_replace` (not `send`) so the value is stored even when there are
        // no receivers yet — the browser page subscribes only after sign-in, and
        // must still see the latest phase (and every one after it).
        self.tx.send_replace(status);
    }

    /// Subscribe to progress updates (used by the status-page SSE endpoint).
    pub fn subscribe(&self) -> watch::Receiver<Status> {
        self.tx.subscribe()
    }

    /// Marked true once the SAML status page has loaded in the user's browser.
    pub fn mark_browser_open(&self) {
        self.browser_open.store(true, Ordering::Relaxed);
    }

    pub fn browser_open(&self) -> bool {
        self.browser_open.load(Ordering::Relaxed)
    }
}

impl Default for Progress {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_kinds_and_terminality() {
        assert_eq!(Status::FetchingConfig.render().0, "loading");
        assert!(!Status::FetchingConfig.is_terminal());
        assert_eq!(Status::Up.render().0, "success");
        assert!(Status::Up.is_terminal());
        let (kind, msg) = Status::Failed("boom\n  again".into()).render();
        assert_eq!(kind, "error");
        // Multi-line errors are flattened so SSE keeps them on one data line.
        assert!(!msg.contains('\n'));
        assert!(msg.contains("boom again"));
        assert!(Status::Failed("x".into()).is_terminal());
    }

    #[tokio::test]
    async fn late_subscriber_sees_current_status() {
        let p = Progress::new();
        p.report(Status::FetchingConfig);
        // A subscriber that arrives after the update still reads the latest value.
        let rx = p.subscribe();
        assert_eq!(*rx.borrow(), Status::FetchingConfig);
        assert!(!p.browser_open());
        p.mark_browser_open();
        assert!(p.browser_open());
    }
}
