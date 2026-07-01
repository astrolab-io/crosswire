// SPDX-License-Identifier: GPL-3.0-or-later
//! The bidirectional tunnel io-loop.
//!
//! Shuttles PPP packets between the gateway TLS stream (transport framing) and
//! `pppd` on the pty (HDLC framing). Runs until either side closes, a framing
//! error occurs, or shutdown is requested.

use crate::core::framer::Framer;
use crate::core::lifecycle::Shutdown;
use crate::core::provider::ByteStream;
use crate::transport::framing::HdlcFramer;
use crate::transport::pty::AsyncPty;
use anyhow::Result;
use bytes::BytesMut;
use std::os::fd::OwnedFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt, split};

const READ_CHUNK: usize = 16 * 1024;

/// Pump framed packets from `reader` to `writer`, deframing with `dec` and
/// reframing with `enc`.
async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    mut dec: Box<dyn Framer>,
    mut enc: Box<dyn Framer>,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = BytesMut::with_capacity(64 * 1024);
    let mut tmp = [0u8; READ_CHUNK];
    loop {
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        while let Some(pkt) = dec.decode(&mut buf)? {
            let mut out = BytesMut::new();
            enc.encode(&pkt, &mut out)?;
            writer.write_all(&out).await?;
        }
    }
}

/// Run the io-loop until a direction ends, an error occurs, or shutdown fires.
pub async fn io_loop(
    tunnel: Box<dyn ByteStream>,
    transport_dec: Box<dyn Framer>,
    transport_enc: Box<dyn Framer>,
    pty_fd: OwnedFd,
    mut shutdown: Shutdown,
) -> Result<()> {
    let (tls_read, tls_write) = split(tunnel);
    let pty = AsyncPty::new(pty_fd)?;
    let (pty_read, pty_write) = split(pty);

    // tunnel (transport frames) -> pty (HDLC frames)
    let mut down = tokio::spawn(pump(
        tls_read,
        pty_write,
        transport_dec,
        Box::new(HdlcFramer::new()),
    ));
    // pty (HDLC frames) -> tunnel (transport frames)
    let mut up = tokio::spawn(pump(
        pty_read,
        tls_write,
        Box::new(HdlcFramer::new()),
        transport_enc,
    ));

    tokio::select! {
        r = &mut down => {
            up.abort();
            log_direction("tunnel→pty", r);
        }
        r = &mut up => {
            down.abort();
            log_direction("pty→tunnel", r);
        }
        _ = shutdown.wait() => {
            tracing::info!("Shutdown requested; stopping io-loop");
            down.abort();
            up.abort();
        }
    }

    Ok(())
}

fn log_direction(dir: &str, r: Result<Result<()>, tokio::task::JoinError>) {
    match r {
        Ok(Ok(())) => tracing::info!("io-loop {} closed", dir),
        Ok(Err(e)) => tracing::warn!("io-loop {} error: {}", dir, e),
        Err(e) if e.is_cancelled() => {}
        Err(e) => tracing::warn!("io-loop {} task failed: {}", dir, e),
    }
}
