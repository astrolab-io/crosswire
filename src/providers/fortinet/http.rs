// SPDX-License-Identifier: GPL-3.0-or-later
//! Minimal HTTP/1.1-over-TLS client with a cookie jar, for the Fortinet auth
//! endpoints. One [`HttpSession`] wraps a single TLS connection.

use anyhow::{Result, bail};
use cookie::{Cookie, CookieJar};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::{SendRequest, handshake};
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

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
    sender: SendRequest<Full<Bytes>>,
    jar: CookieJar,
}

impl HttpSession {
    /// Perform the HTTP/1.1 handshake over an established TLS stream.
    pub async fn new(stream: SslStream<TcpStream>, host: &str, port: u16) -> Result<Self> {
        let (sender, conn) = handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("HTTP connection closed: {}", e);
            }
        });
        Ok(Self {
            host: host.to_string(),
            port,
            sender,
            jar: CookieJar::new(),
        })
    }

    /// Seed a cookie (e.g. an externally supplied SVPNCOOKIE).
    pub fn set_cookie(&mut self, name: &str, value: &str) {
        self.jar
            .add_original(Cookie::new(name.to_string(), value.to_string()));
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        self.jar.get(name).map(|c| c.value().to_string())
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

            let mut builder = Request::builder()
                .method(method.clone())
                .uri(&full_uri)
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

            let request = builder.body(Full::new(Bytes::from(body.clone())))?;
            let response: Response<hyper::body::Incoming> =
                self.sender.send_request(request).await?;

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
