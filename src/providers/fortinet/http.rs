// SPDX-License-Identifier: GPL-3.0-or-later
//! Minimal HTTP/1.1-over-TLS client with a cookie jar, for the Fortinet auth
//! endpoints. One [`HttpSession`] wraps a single TLS connection — and transparently
//! re-establishes it when the gateway drops the keep-alive connection mid-flow.
//!
//! FortiGate readily closes an accepted TLS connection without answering during
//! the brief window right after a prior SSL-VPN session is torn down (and it may
//! send `Connection: close` between our allocation-handshake GETs). hyper surfaces
//! that as `operation was canceled` / `connection was not ready`. A single-shot
//! client turns that transient into a fatal connect failure, so on a canceled /
//! closed connection we re-dial a fresh TLS connection and retry the (idempotent)
//! request a bounded number of times with backoff before giving up.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use cookie::{Cookie, CookieJar};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::{SendRequest, handshake};
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;

use crate::transport::tls::TlsFactory;

/// How many times to re-dial + retry a request whose connection was dropped
/// before it completed. With [`backoff`] this spans ~12s — comfortably inside
/// NetworkManager's 60s connect timeout, while riding over the gateway's
/// post-teardown cool-down so an immediate reconnect usually succeeds first try.
const MAX_RECONNECTS: u32 = 5;

/// Backoff before the Nth reconnect attempt (1-based): 0.5s, 1s, 2s, 4s, 5s…
fn backoff(attempt: u32) -> Duration {
    let ms = 500u64.saturating_mul(1u64 << attempt.saturating_sub(1).min(4));
    Duration::from_millis(ms.min(5_000))
}

/// A dropped-before-completion connection error is safe to retry on a fresh
/// connection: the request either never reached the gateway (canceled: the
/// connection was never ready) or the connection was closed without a response.
fn is_retryable(err: &hyper::Error) -> bool {
    err.is_canceled() || err.is_closed()
}

pub struct HttpResponse {
    pub status: hyper::StatusCode,
    pub body: Bytes,
}

impl HttpResponse {
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
}

pub struct HttpSession {
    host: String,
    port: u16,
    /// Retained so we can re-dial the gateway if the keep-alive drops mid-flow.
    tls: TlsFactory,
    sender: SendRequest<Full<Bytes>>,
    jar: CookieJar,
}

impl HttpSession {
    /// Open a verified TLS connection to the gateway and perform the HTTP/1.1
    /// handshake. The [`TlsFactory`] is kept so [`reconnect`](Self::reconnect)
    /// can re-dial an identical connection if this one is dropped.
    pub async fn connect(tls: TlsFactory) -> Result<Self> {
        let host = tls.host().to_string();
        let port = tls.port();
        let sender = Self::dial(&tls).await?;
        Ok(Self {
            host,
            port,
            tls,
            sender,
            jar: CookieJar::new(),
        })
    }

    /// Dial a fresh TLS connection to the gateway and spawn its connection task.
    async fn dial(tls: &TlsFactory) -> Result<SendRequest<Full<Bytes>>> {
        let stream = tls.connect().await?;
        let (sender, conn) = handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("HTTP connection closed: {}", e);
            }
        });
        Ok(sender)
    }

    /// Replace the underlying connection after the gateway dropped the old one.
    async fn reconnect(&mut self) -> Result<()> {
        self.sender = Self::dial(&self.tls).await?;
        Ok(())
    }

    /// Seed a cookie (e.g. an externally supplied SVPNCOOKIE).
    pub fn set_cookie(&mut self, name: &str, value: &str) {
        self.jar
            .add_original(Cookie::new(name.to_string(), value.to_string()));
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        self.jar.get(name).map(|c| c.value().to_string())
    }

    /// Construct a fresh request (headers + current cookies + body). Rebuilt for
    /// every send attempt, since `send_request` consumes the request and a retry
    /// runs it on a new connection.
    fn build_request(&self, method: &Method, full_uri: &str, body: &str) -> Result<Request<Full<Bytes>>> {
        let mut builder = Request::builder()
            .method(method.clone())
            .uri(full_uri)
            .header("Host", format!("{}:{}", self.host, self.port))
            .header("User-Agent", "crosswire");

        let cookies: Vec<String> = self
            .jar
            .iter()
            .map(|c| format!("{}={}", c.name(), c.value()))
            .collect();
        if !cookies.is_empty() {
            builder = builder.header("Cookie", cookies.join("; "));
        }
        if method == Method::POST {
            builder = builder.header("Content-Type", "application/x-www-form-urlencoded");
        }
        Ok(builder.body(Full::new(Bytes::from(body.to_string())))?)
    }

    /// Send one request, transparently re-dialing and retrying if the gateway
    /// drops the connection before the request completes.
    async fn send_with_reconnect(
        &mut self,
        method: &Method,
        full_uri: &str,
        body: &str,
    ) -> Result<Response<hyper::body::Incoming>> {
        let mut attempt = 0;
        loop {
            let request = self.build_request(method, full_uri, body)?;
            match self.sender.send_request(request).await {
                Ok(response) => return Ok(response),
                Err(e) if is_retryable(&e) && attempt < MAX_RECONNECTS => {
                    attempt += 1;
                    let wait = backoff(attempt);
                    tracing::warn!(
                        "gateway dropped connection for {method} {full_uri} ({e}); \
                         reconnecting in {wait:?} (attempt {attempt}/{MAX_RECONNECTS})"
                    );
                    tokio::time::sleep(wait).await;
                    self.reconnect()
                        .await
                        .context("re-dialing gateway after a dropped connection")?;
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e)
                        .context(format!("request to {full_uri} failed")));
                }
            }
        }
    }

    pub async fn get(&mut self, uri: &str, allow_redirects: bool) -> Result<HttpResponse> {
        self.request(Method::GET, uri, String::new(), allow_redirects)
            .await
    }

    pub async fn post(&mut self, uri: &str, body: String) -> Result<HttpResponse> {
        self.request(Method::POST, uri, body, false).await
    }

    pub async fn request(
        &mut self,
        method: Method,
        uri: &str,
        body: String,
        allow_redirects: bool,
    ) -> Result<HttpResponse> {
        let mut uri = uri.to_string();
        let mut redirects = 0u32;

        loop {
            let full_uri = if uri.starts_with('/') {
                format!("https://{}:{}{}", self.host, self.port, uri)
            } else {
                uri.clone()
            };

            let response = self.send_with_reconnect(&method, &full_uri, &body).await?;

            let status = response.status();
            let headers = response.headers().clone();
            let location = headers
                .get("Location")
                .and_then(|h| h.to_str().ok())
                .map(str::to_string);

            for v in headers.get_all("Set-Cookie") {
                if let Ok(s) = v.to_str()
                    && let Ok(c) = Cookie::parse(s.to_string())
                {
                    self.jar.add_original(c.into_owned());
                }
            }

            let body_bytes = response.into_body().collect().await?.to_bytes();

            if status.is_redirection()
                && allow_redirects
                && let Some(loc) = location
            {
                if redirects >= 10 {
                    bail!("too many redirects for {}", full_uri);
                }
                tracing::debug!("{} redirect → {}", status, loc);
                uri = loc;
                redirects += 1;
                continue;
            }

            return Ok(HttpResponse {
                status,
                body: body_bytes,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_RECONNECTS, backoff};
    use std::time::Duration;

    #[test]
    fn backoff_grows_then_caps() {
        // 1-based: 0.5s, 1s, 2s, 4s, then capped at 5s.
        assert_eq!(backoff(1), Duration::from_millis(500));
        assert_eq!(backoff(2), Duration::from_millis(1_000));
        assert_eq!(backoff(3), Duration::from_millis(2_000));
        assert_eq!(backoff(4), Duration::from_millis(4_000));
        assert_eq!(backoff(5), Duration::from_millis(5_000)); // 8s capped to 5s
        assert_eq!(backoff(9), Duration::from_millis(5_000)); // stays capped
    }

    #[test]
    fn total_retry_budget_fits_nm_connect_timeout() {
        // Sum of all backoffs must stay well under NM's 60s connect timeout,
        // or an in-flight reconnect would outlive the connection attempt.
        let total: Duration = (1..=MAX_RECONNECTS).map(backoff).sum();
        assert!(total < Duration::from_secs(30), "retry budget {total:?} too large");
    }
}
