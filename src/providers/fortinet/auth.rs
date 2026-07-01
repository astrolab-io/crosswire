// SPDX-License-Identifier: GPL-3.0-or-later
//! Fortinet authentication flows: username/password and SAML/SSO.

use super::http::HttpSession;
use crate::cli::Config;
use crate::net::browser;
use anyhow::{Result, bail};
use axum::{
    Router,
    extract::{Query, State},
    response::Html,
    routing::get,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::{Mutex, oneshot};

pub const SVPNCOOKIE: &str = "SVPNCOOKIE";

/// Extract `key=value` from a gateway response body. Values end at `&`, `,`,
/// or whitespace — matching upstream `get_value_from_response`.
pub fn parse_response_value(body: &str, key: &str) -> Option<String> {
    let pat = format!("{}=", key);
    let start = body.find(&pat)? + pat.len();
    let rest = &body[start..];
    let end = rest
        .find(|c: char| c == '&' || c == ',' || c.is_whitespace())
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// POST credentials to `/remote/logincheck` and validate the response.
pub async fn password_login(http: &mut HttpSession, config: &Config) -> Result<()> {
    let mut body = String::from("ajax=1");
    if let Some(user) = &config.username {
        body.push_str(&format!("&username={}", urlencoding::encode(user)));
    }
    if let Some(pass) = &config.password {
        body.push_str(&format!("&credential={}", urlencoding::encode(pass)));
    }
    if let Some(realm) = &config.realm {
        body.push_str(&format!("&realm={}", urlencoding::encode(realm)));
    }

    let res = http.post("/remote/logincheck", body).await?;
    let text = res.text().into_owned();
    tracing::debug!("logincheck response: {}", text);

    // A challenge is signalled by `tokeninfo=` with no cookie yet; otherwise a
    // ret=1 response is already authenticated.
    if parse_response_value(&text, "tokeninfo").is_some() && http.cookie(SVPNCOOKIE).is_none() {
        handle_challenge(http, config, &text).await?;
    } else {
        match parse_response_value(&text, "ret").as_deref() {
            Some("1") => {}
            other => bail!(
                "Authentication failed (ret={})",
                other.unwrap_or("<missing>")
            ),
        }
    }

    if http.cookie(SVPNCOOKIE).is_none() {
        bail!("Login succeeded but no {} cookie was returned", SVPNCOOKIE);
    }
    Ok(())
}

/// Drive the FortiOS two-factor challenge: either a FortiToken Mobile push or an
/// interactive/config-supplied OTP code, re-POSTed to `/remote/logincheck`.
async fn handle_challenge(http: &mut HttpSession, config: &Config, challenge: &str) -> Result<()> {
    let magic = parse_response_value(challenge, "magic").unwrap_or_default();
    let reqid = parse_response_value(challenge, "reqid").unwrap_or_default();
    let polid = parse_response_value(challenge, "polid").unwrap_or_default();
    let grp = parse_response_value(challenge, "grp").unwrap_or_default();

    let base = |extra: &str| -> String {
        let mut b = String::from("ajax=1");
        if let Some(user) = &config.username {
            b.push_str(&format!("&username={}", urlencoding::encode(user)));
        }
        if let Some(realm) = &config.realm {
            b.push_str(&format!("&realm={}", urlencoding::encode(realm)));
        }
        b.push_str(&format!(
            "&reqid={}&polid={}&grp={}&magic={}",
            reqid, polid, grp, magic
        ));
        b.push_str(extra);
        b
    };

    // FortiToken Mobile push: no code needed; the gateway blocks until the user
    // approves on their device.
    if config.otp.is_none() && !config.no_ftm_push {
        tracing::info!("Waiting for FortiToken Mobile push approval...");
        let res = http
            .post("/remote/logincheck", base("&code=&code2=&ftmpush=1"))
            .await?;
        let text = res.text();
        if parse_response_value(&text, "ret").as_deref() == Some("1")
            || http.cookie(SVPNCOOKIE).is_some()
        {
            return Ok(());
        }
        tracing::warn!("FortiToken push not approved; falling back to OTP entry.");
    }

    // OTP code: from config, else prompt (via pinentry or TTY).
    let code = match &config.otp {
        Some(o) => o.clone(),
        None => {
            let prompt = config
                .otp_prompt
                .clone()
                .unwrap_or_else(|| "Two-factor token: ".to_string());
            crate::secret::read_secret(&prompt, config.pinentry.as_deref())?
        }
    };

    if config.otp_delay > 0 {
        tokio::time::sleep(std::time::Duration::from_secs(config.otp_delay)).await;
    }

    let extra = format!("&code={}&code2=", urlencoding::encode(code.trim()));
    let res = http.post("/remote/logincheck", base(&extra)).await?;
    let text = res.text();
    tracing::debug!("2FA response: {}", text);

    if parse_response_value(&text, "ret").as_deref() != Some("1")
        && http.cookie(SVPNCOOKIE).is_none()
    {
        bail!("Two-factor authentication failed");
    }
    Ok(())
}

#[derive(Deserialize)]
struct SamlQuery {
    id: String,
}

/// Run the SAML login flow: start a local callback server, open the browser at
/// the gateway's SAML entry point, capture the session id, and exchange it for
/// an SVPNCOOKIE via `/remote/saml/auth_id`.
pub async fn saml_login(http: &mut HttpSession, config: &Config, port: u16) -> Result<()> {
    let session_id = capture_saml_id(config, port).await?;
    tracing::info!("Received SAML session id.");

    let uri = format!(
        "/remote/saml/auth_id?id={}",
        urlencoding::encode(&session_id)
    );
    let res = http.get(&uri, false).await?;
    if !res.status.is_success() && !res.status.is_redirection() {
        bail!("SAML auth_id exchange failed: HTTP {}", res.status);
    }

    if http.cookie(SVPNCOOKIE).is_none() {
        bail!(
            "SAML login completed but no {} cookie was returned",
            SVPNCOOKIE
        );
    }
    Ok(())
}

async fn capture_saml_id(config: &Config, port: u16) -> Result<String> {
    let (tx, rx) = oneshot::channel();
    let state = Arc::new(Mutex::new(Some(tx)));

    let app = Router::new()
        .route("/", get(saml_callback))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    tracing::info!("Listening for SAML callback on 127.0.0.1:{}", port);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = shutdown_rx.await;
    });
    let server_task = tokio::spawn(async move {
        if let Err(e) = server.await {
            tracing::error!("SAML server error: {}", e);
        }
    });

    let sso_url = format!(
        "https://{}:{}/remote/saml/start?redirect=1",
        config.host, config.port
    );
    browser::open_url(&sso_url);

    let id = rx
        .await
        .map_err(|_| anyhow::anyhow!("SAML listener closed early"))?;
    let _ = shutdown_tx.send(());
    let _ = server_task.await;
    Ok(id)
}

async fn saml_callback(
    State(tx_state): State<Arc<Mutex<Option<oneshot::Sender<String>>>>>,
    Query(query): Query<SamlQuery>,
) -> Html<&'static str> {
    if let Some(tx) = tx_state.lock().await.take() {
        let _ = tx.send(query.id);
    }
    Html(
        "<!DOCTYPE html><html><body>\
         SAML session id received. The VPN will now be established.<br>\
         You may close this tab.\
         <script>window.setTimeout(() => window.close(), 5000);</script>\
         </body></html>",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_response_value() {
        assert_eq!(
            parse_response_value("ret=1,redir=/x", "ret").as_deref(),
            Some("1")
        );
        assert_eq!(
            parse_response_value("ret=1,redir=/x", "redir").as_deref(),
            Some("/x")
        );
        assert_eq!(
            parse_response_value("foo=bar&ret=0", "ret").as_deref(),
            Some("0")
        );
        assert_eq!(
            parse_response_value("tokeninfo=... ,x", "tokeninfo").as_deref(),
            Some("...")
        );
        assert_eq!(parse_response_value("nope", "ret"), None);
    }
}
