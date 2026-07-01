// SPDX-License-Identifier: GPL-3.0-or-later
mod cli;
mod core;
mod net;
mod providers;
mod secret;
mod transport;

use crate::core::engine;
use crate::core::lifecycle::ShutdownController;
use crate::providers::fortinet::Fortinet;
use anyhow::{Result, bail};
use nix::unistd::Uid;
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // A closed gateway socket must not kill the process (upstream: SIG_IGN).
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let config = cli::Config::parse_and_merge()?;
    init_logging(config.verbose);

    if config.host.is_empty() {
        bail!("no gateway host specified (pass <host> or set 'host' in the config file)");
    }
    if !cfg!(debug_assertions) && !Uid::effective().is_root() {
        bail!("crosswire must be run as root");
    }

    let config = Arc::new(config);

    // Shutdown on SIGINT/SIGTERM.
    let (controller, shutdown) = ShutdownController::new();
    tokio::spawn(async move {
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("failed to install SIGTERM handler: {}", e);
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
        tracing::info!("Signal received; shutting down.");
        controller.trigger();
    });

    let provider = Box::new(Fortinet);
    let net = net::configurator();

    engine::run(provider, net, config, shutdown).await
}

fn init_logging(verbose: u8) {
    let filter = match verbose {
        0 => "warn,crosswire=info",
        1 => "info,crosswire=debug",
        2 => "debug,crosswire=trace",
        _ => "trace",
    };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(filter))
        .with(tracing_subscriber::fmt::layer())
        .init();
}
