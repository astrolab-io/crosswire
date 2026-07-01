// SPDX-License-Identifier: GPL-3.0-or-later
//! Provider-neutral types and the [`VpnProvider`] contract.
//!
//! A provider implements the gateway-specific parts of the flow — authenticate,
//! fetch the network parameters, and open the raw tunnel stream — while the
//! engine owns everything generic (TLS, pppd, network config, lifecycle).

use crate::cli::Config;
use crate::core::framer::Framer;
use crate::transport::tls::TlsFactory;
use anyhow::Result;
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

/// A duplex byte stream (e.g. a TLS connection) usable as the tunnel transport.
pub trait ByteStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ByteStream for T {}

/// An authenticated session, provider-neutral (typically a cookie/token).
#[derive(Clone, Debug)]
pub struct Session {
    pub cookie: String,
}

/// One routing-table entry to install through the tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub dest: Ipv4Addr,
    pub prefix: u8,
}

/// Network parameters returned by the gateway after authentication.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TunnelParams {
    pub assigned_addr: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub dns_suffix: Option<String>,
    /// Split-tunnel routes. Empty means full-tunnel (default route via VPN).
    pub routes: Vec<Route>,
    pub mtu: Option<u32>,
}

/// Shared context handed to a provider: config plus a verified TLS factory.
pub struct ProviderContext {
    pub config: Arc<Config>,
    tls: TlsFactory,
}

impl ProviderContext {
    pub fn new(config: Arc<Config>, tls: TlsFactory) -> Self {
        Self { config, tls }
    }

    /// Open a fresh verified TLS connection to the gateway.
    pub async fn connect_tls(&self) -> Result<SslStream<TcpStream>> {
        self.tls.connect().await
    }

    pub fn tls(&self) -> &TlsFactory {
        &self.tls
    }
}

/// The gateway-specific contract the engine drives.
#[async_trait]
pub trait VpnProvider: Send + Sync {
    /// Human-readable provider name (for logs).
    fn name(&self) -> &'static str;

    /// Authenticate and return a session (cookie/token).
    async fn authenticate(&self, ctx: &ProviderContext) -> Result<Session>;

    /// Fetch the network parameters (assigned addr, DNS, routes).
    async fn fetch_params(&self, ctx: &ProviderContext, session: &Session) -> Result<TunnelParams>;

    /// Open the raw tunnel byte stream (already switched to tunneling mode).
    async fn open_tunnel(
        &self,
        ctx: &ProviderContext,
        session: &Session,
    ) -> Result<Box<dyn ByteStream>>;

    /// Best-effort logout for the session (called during teardown).
    async fn logout(&self, ctx: &ProviderContext, session: &Session) -> Result<()>;

    /// The framer for the transport (gateway) side of the tunnel.
    fn transport_framer(&self) -> Box<dyn Framer>;
}
