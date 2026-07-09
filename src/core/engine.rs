// SPDX-License-Identifier: GPL-3.0-or-later
//! The provider-agnostic connection engine.
//!
//! Drives the generic pipeline — authenticate → fetch params → spawn pppd →
//! open tunnel → io-loop → teardown — against trait objects, and wraps it in an
//! optional `--persistent` reconnect loop. All teardown (network restore, pppd
//! reap, logout) happens via RAII/`Drop` and explicit best-effort logout, on
//! every exit path.

use crate::cli::Config;
use crate::core::io::io_loop;
use crate::core::lifecycle::Shutdown;
use crate::core::progress::{Progress, Status};
use crate::core::provider::{ProviderContext, Session, VpnProvider};
use crate::net::NetworkConfigurator;
use crate::net::wait_for_iface;
use crate::transport::ppp::spawn_pppd;
use crate::transport::tls::TlsFactory;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;

const IFACE_TIMEOUT: Duration = Duration::from_secs(60);

/// Run the VPN, honoring `--persistent`. Returns when shutdown is requested (or
/// on a fatal, non-recoverable error in one-shot mode).
pub async fn run(
    provider: Box<dyn VpnProvider>,
    net: Box<dyn NetworkConfigurator>,
    config: Arc<Config>,
    mut shutdown: Shutdown,
) -> Result<()> {
    let progress = Progress::new();
    let ctx = ProviderContext::new(config.clone(), TlsFactory::from_config(&config), progress.clone());

    if config.persistent == 0 {
        let result = run_once(&*provider, &ctx, &*net, &config, shutdown).await;
        if let Err(e) = &result {
            report_failure(&progress, e).await;
        }
        return result;
    }

    while !shutdown.is_triggered() {
        if let Err(e) = run_once(&*provider, &ctx, &*net, &config, shutdown.clone()).await {
            tracing::error!("Tunnel terminated: {:#}", e);
            report_failure(&progress, &e).await;
        }
        if shutdown.is_triggered() {
            break;
        }
        tracing::info!("Reconnecting in {}s...", config.persistent);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(config.persistent)) => {}
            _ = shutdown.wait() => break,
        }
    }
    Ok(())
}

/// One full connection lifecycle. Logout is always attempted once a session is
/// established; network + pppd teardown happen via `Drop`.
async fn run_once(
    provider: &dyn VpnProvider,
    ctx: &ProviderContext,
    net: &dyn NetworkConfigurator,
    config: &Config,
    shutdown: Shutdown,
) -> Result<()> {
    tracing::info!("Connecting via {} provider", provider.name());
    let session = provider.authenticate(ctx).await?;
    tracing::info!("Authenticated.");
    ctx.progress().report(Status::Authenticated);

    let result = run_session(provider, ctx, net, config, &session, shutdown).await;

    // Best-effort logout on every exit path once authenticated.
    if let Err(e) = provider.logout(ctx, &session).await {
        tracing::debug!("Logout failed: {}", e);
    } else {
        tracing::debug!("Logged out.");
    }

    result
}

async fn run_session(
    provider: &dyn VpnProvider,
    ctx: &ProviderContext,
    net: &dyn NetworkConfigurator,
    config: &Config,
    session: &Session,
    shutdown: Shutdown,
) -> Result<()> {
    ctx.progress().report(Status::FetchingConfig);
    let params = provider.fetch_params(ctx, session).await?;
    tracing::info!("Received tunnel parameters: {:?}", params);

    ctx.progress().report(Status::StartingTunnel);
    // pppd guard reaps on drop (end of this scope, any exit path).
    let (_pppd, master_fd) = spawn_pppd(config, &config.pppd_ifname, &params)?;
    tracing::info!("Spawned pppd on {}", config.pppd_ifname);

    let tunnel = provider.open_tunnel(ctx, session).await?;
    tracing::info!("Switched to tunneling mode.");

    let io_handle = tokio::spawn(io_loop(
        tunnel,
        provider.transport_framer(),
        provider.transport_framer(),
        master_fd,
        shutdown,
    ));

    // Bring up the interface, then apply network config (restored on drop).
    ctx.progress().report(Status::ConfiguringNetwork);
    let setup = async {
        wait_for_iface(&config.pppd_ifname, IFACE_TIMEOUT).await?;
        net.apply(&params, &config.pppd_ifname, config)
    }
    .await;

    match setup {
        Ok(applied) => {
            let _applied = applied; // restores routes/DNS/addr on drop
            tracing::info!("VPN is up.");
            ctx.progress().report(Status::Up);
            let _ = io_handle.await;
            Ok(())
        }
        Err(e) => {
            io_handle.abort();
            let _ = io_handle.await;
            Err(e)
        }
    }
    // _pppd dropped here → SIGTERM + reap.
}

/// Publish a terminal failure to the progress bus. If a SAML status page is open
/// in the browser, linger briefly so it can render the error badge (and run its
/// own close timer) before the process exits and tears the local server down.
async fn report_failure(progress: &Progress, err: &anyhow::Error) {
    progress.report(Status::Failed(format!("{err:#}")));
    if progress.browser_open() {
        tokio::time::sleep(Duration::from_secs(4)).await;
    }
}
