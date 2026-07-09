// SPDX-License-Identifier: GPL-3.0-or-later
//! The local SAML callback + live status page.
//!
//! During a SAML login we open the user's browser at the gateway's SAML entry
//! point; it redirects back to `http://127.0.0.1:<port>/?id=<session-id>`. That
//! request lands on [`saml_callback`], which captures the id and returns a small
//! page that stays open and subscribes to `/events` (Server-Sent Events). The
//! engine reports each connection phase through [`Progress`], so the page shows a
//! live "connecting…" state and finally a success or error badge — then closes
//! itself a few seconds later. The server outlives sign-in and shuts down a few
//! seconds after a terminal [`Status`] (or when the connection tears down).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::{
    Router,
    extract::{Query, State},
    response::{
        Html,
        sse::{Event, KeepAlive, Sse},
    },
    routing::get,
};
use futures::stream::{self, Stream};
use serde::Deserialize;
use tokio::sync::{Mutex, oneshot};

use crate::core::progress::Progress;

/// How long the status server lingers after a terminal status, giving the page
/// time to render the badge and run its own close timer before we shut down.
const TERMINAL_GRACE: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct SamlQuery {
    id: String,
}

#[derive(Clone)]
struct AppState {
    /// Fires once, with the captured SAML session id.
    id_tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
    progress: Progress,
}

/// Start the callback + status server, open the browser, and return the captured
/// SAML session id. The server keeps running (serving the live status page) until
/// a terminal status is reported; it is not torn down when this returns.
pub async fn capture_saml_id(
    host: &str,
    port_gateway: u16,
    local_port: u16,
    progress: Progress,
) -> Result<String> {
    let (tx, rx) = oneshot::channel();
    let state = AppState {
        id_tx: Arc::new(Mutex::new(Some(tx))),
        progress: progress.clone(),
    };

    let app = router(state);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port)).await?;
    tracing::info!("Listening for SAML callback on 127.0.0.1:{}", local_port);

    // Shut down a few seconds after the connection reaches a terminal state, or
    // immediately once every Progress sender is gone (connection torn down).
    let shutdown = {
        let mut rx = progress.subscribe();
        async move {
            loop {
                if rx.borrow().is_terminal() {
                    break;
                }
                if rx.changed().await.is_err() {
                    return; // senders dropped → stop serving now
                }
            }
            tokio::time::sleep(TERMINAL_GRACE).await;
        }
    };

    // Detached: the page must keep updating after we return the id below.
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
        {
            tracing::error!("SAML status server error: {}", e);
        }
    });

    let sso_url = format!("https://{host}:{port_gateway}/remote/saml/start?redirect=1");
    crate::net::browser::open_url(&sso_url);

    rx.await
        .map_err(|_| anyhow::anyhow!("SAML listener closed early"))
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(saml_callback))
        .route("/events", get(status_events))
        .with_state(state)
}

/// The browser lands here after the IdP round-trip. Capture the session id and
/// return the live status page.
async fn saml_callback(
    State(state): State<AppState>,
    Query(query): Query<SamlQuery>,
) -> Html<&'static str> {
    state.progress.mark_browser_open();
    if let Some(tx) = state.id_tx.lock().await.take() {
        let _ = tx.send(query.id);
    }
    Html(STATUS_PAGE)
}

/// SSE stream of connection phases. Emits the current status immediately, then
/// one event per change, until the Progress senders are dropped.
async fn status_events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.progress.subscribe();
    // `first` makes the initial iteration emit the current value without waiting
    // for a change, so a freshly-connected page paints immediately.
    let stream = stream::unfold((rx, true), |(mut rx, first)| async move {
        if !first && rx.changed().await.is_err() {
            return None;
        }
        let status = rx.borrow_and_update().clone();
        let (kind, text) = status.render();
        let event = Event::default().event(kind).data(text);
        Some((Ok(event), (rx, false)))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Self-contained status page: a centered indicator + status line that tracks the
/// SSE events, turning into a success or error badge and closing 3s later.
const STATUS_PAGE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CrossWire — Connecting…</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #0f172a; color: #e2e8f0;
  }
  @media (prefers-color-scheme: light) { body { background: #f1f5f9; color: #0f172a; } }
  .card {
    text-align: center; padding: 2.5rem 3rem; max-width: 22rem;
  }
  .indicator {
    width: 64px; height: 64px; margin: 0 auto 1.5rem; position: relative;
  }
  .spinner {
    width: 64px; height: 64px; border-radius: 50%;
    border: 5px solid rgba(148,163,184,.25); border-top-color: #38bdf8;
    animation: spin .9s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .badge {
    width: 64px; height: 64px; border-radius: 50%; display: none;
    align-items: center; justify-content: center; font-size: 34px; font-weight: 700; color: #fff;
  }
  .badge svg { width: 34px; height: 34px; stroke: #fff; stroke-width: 3.5; fill: none;
    stroke-linecap: round; stroke-linejoin: round; }
  h1 { font-size: 1.15rem; font-weight: 600; margin: 0 0 .4rem; }
  .status { font-size: .95rem; color: #94a3b8; min-height: 1.4em; margin: 0; }
  @media (prefers-color-scheme: light) { .status { color: #475569; } }
  .hint { font-size: .78rem; color: #64748b; margin-top: 1.4rem; opacity: 0; transition: opacity .3s; }
  body.done .hint { opacity: 1; }
  body.success .badge.success { display: flex; background: #16a34a; }
  body.error   .badge.error   { display: flex; background: #dc2626; }
  body.success .spinner, body.error .spinner { display: none; }
  body.success h1, body.error h1 { }
</style>
</head>
<body>
  <div class="card">
    <div class="indicator">
      <div class="spinner"></div>
      <div class="badge success"><svg viewBox="0 0 24 24"><polyline points="4 12 10 18 20 6"/></svg></div>
      <div class="badge error"><svg viewBox="0 0 24 24"><line x1="6" y1="6" x2="18" y2="18"/><line x1="18" y1="6" x2="6" y2="18"/></svg></div>
    </div>
    <h1 id="title">Connecting to VPN…</h1>
    <p class="status" id="status">Starting…</p>
    <p class="hint">This tab will close automatically.</p>
  </div>
<script>
  var statusEl = document.getElementById('status');
  var titleEl = document.getElementById('title');
  var es = new EventSource('/events');
  function setStatus(text) { statusEl.textContent = text; }
  es.addEventListener('loading', function (e) { setStatus(e.data); });
  es.addEventListener('success', function (e) {
    finish('success', 'Connected', e.data);
  });
  es.addEventListener('error', function (e) {
    // Only a payload-bearing 'error' event is a real connection error; the
    // browser also fires a data-less 'error' on transient stream hiccups.
    if (e.data) finish('error', 'Connection failed', e.data);
  });
  function finish(kind, title, text) {
    es.close();
    titleEl.textContent = title;
    setStatus(text);
    document.body.classList.add(kind, 'done');
    setTimeout(function () { window.close(); }, 3000);
  }
</script>
</body>
</html>"##;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::progress::Status;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// End-to-end check of the SSE wiring: a client connected to `/events` gets
    /// the current phase immediately, then every subsequent phase — with the
    /// event names (`loading`/`success`) the status page listens for.
    #[tokio::test]
    async fn events_stream_reflects_progress() {
        let progress = Progress::new();
        let state = AppState {
            id_tx: Arc::new(Mutex::new(None)),
            progress: progress.clone(),
        };
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router(state)).await;
        });

        progress.report(Status::FetchingConfig);

        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"GET /events HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        // The current phase is delivered right away…
        let head = read_until(&mut sock, "Fetching VPN configuration").await;
        assert!(
            head.contains("event:loading") || head.contains("event: loading"),
            "{head}"
        );

        // …and a later phase arrives on the same stream.
        progress.report(Status::Up);
        let more = read_until(&mut sock, "You're all set").await;
        assert!(
            more.contains("event:success") || more.contains("event: success"),
            "{more}"
        );
    }

    /// Read from the socket until `needle` appears (or a short timeout), so the
    /// test doesn't depend on SSE chunk boundaries.
    async fn read_until(sock: &mut tokio::net::TcpStream, needle: &str) -> String {
        let mut acc = String::new();
        let mut buf = [0u8; 1024];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let n = tokio::time::timeout_at(deadline, sock.read(&mut buf))
                .await
                .expect("timed out waiting for SSE data")
                .expect("socket read");
            if n == 0 {
                break;
            }
            acc.push_str(&String::from_utf8_lossy(&buf[..n]));
            if acc.contains(needle) {
                break;
            }
        }
        acc
    }
}
