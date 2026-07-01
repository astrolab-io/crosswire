// SPDX-License-Identifier: GPL-3.0-or-later
//! Generic, object-safe framing abstraction used by the engine's io-loop.
//!
//! Both sides of the tunnel need framing: the transport side (gateway-specific,
//! e.g. Fortinet's 6-byte `0x5050` header) and the link side (HDLC toward pppd).
//! `tokio_util`'s `Encoder`/`Decoder` are generic and awkward to box, so we use
//! this small trait instead — it mirrors their semantics but stays `dyn`-safe.

use anyhow::Result;
use bytes::BytesMut;

/// Frames and deframes a byte stream into whole PPP packets.
pub trait Framer: Send {
    /// Try to decode one frame from `src`. Returns `Ok(None)` if more bytes are
    /// needed. Consumes the frame's bytes from `src` when one is produced.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>>;

    /// Encode one payload into `dst`.
    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<()>;
}
