// SPDX-License-Identifier: GPL-3.0-or-later
//! FortiGate SSL VPN provider.

mod auth;
mod http;
mod status;
mod xml;

use crate::core::framer::Framer;
use crate::core::provider::{ByteStream, ProviderContext, Session, TunnelParams, VpnProvider};
use crate::transport::framing::FortiFramer;
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use http::HttpSession;
use tokio::io::AsyncWriteExt;

pub struct Fortinet;

impl Fortinet {
    async fn http_session(&self, ctx: &ProviderContext) -> Result<HttpSession> {
        // The session keeps the factory so it can re-dial if the gateway drops
        // the keep-alive connection mid-flow (common right after a prior session
        // teardown, when an immediate reconnect races the gateway's cool-down).
        HttpSession::connect(ctx.tls().clone()).await
    }
}

#[async_trait]
impl VpnProvider for Fortinet {
    fn name(&self) -> &'static str {
        "fortinet"
    }

    async fn authenticate(&self, ctx: &ProviderContext) -> Result<Session> {
        let config = &ctx.config;

        // 1. Externally supplied cookie (flag or stdin) short-circuits login.
        if config.cookie_on_stdin {
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .context("reading cookie from stdin")?;
            let cookie = line.trim().to_string();
            if cookie.is_empty() {
                bail!("empty cookie read from stdin");
            }
            return Ok(Session { cookie });
        }
        if let Some(cookie) = &config.cookie {
            return Ok(Session {
                cookie: cookie.clone(),
            });
        }

        // 2. Interactive login (SAML or username/password).
        let mut session = self.http_session(ctx).await?;
        if let Some(port) = config.saml_port {
            auth::saml_login(&mut session, config, port, ctx.progress().clone()).await?;
        } else {
            auth::password_login(&mut session, config).await?;
        }

        let cookie = session
            .cookie(auth::SVPNCOOKIE)
            .context("authentication produced no session cookie")?;
        Ok(Session { cookie })
    }

    async fn fetch_params(&self, ctx: &ProviderContext, session: &Session) -> Result<TunnelParams> {
        let mut http = self.http_session(ctx).await?;
        http.set_cookie(auth::SVPNCOOKIE, &session.cookie);

        // Allocation handshake (responses are not needed, only side effects).
        let _ = http.get("/remote/index", true).await;
        let _ = http.get("/remote/fortisslvpn", true).await;

        let res = http.get("/remote/fortisslvpn_xml", false).await?;
        if !res.status.is_success() {
            bail!("config fetch failed: HTTP {}", res.status);
        }
        let text = res.text();
        tracing::debug!("VPN config XML: {}", text);
        xml::parse_tunnel_params(&text)
    }

    async fn open_tunnel(
        &self,
        ctx: &ProviderContext,
        session: &Session,
    ) -> Result<Box<dyn ByteStream>> {
        let mut tls = ctx.connect_tls().await?;
        let req = format!(
            "GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\nCookie: {}={}\r\n\r\n",
            auth::SVPNCOOKIE,
            session.cookie
        );
        tls.write_all(req.as_bytes()).await?;
        Ok(Box::new(tls))
    }

    async fn logout(&self, ctx: &ProviderContext, session: &Session) -> Result<()> {
        let mut http = self.http_session(ctx).await?;
        http.set_cookie(auth::SVPNCOOKIE, &session.cookie);
        http.get("/remote/logout", false).await?;
        Ok(())
    }

    fn transport_framer(&self) -> Box<dyn Framer> {
        Box::new(FortiFramer)
    }
}
