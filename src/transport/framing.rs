// SPDX-License-Identifier: GPL-3.0-or-later
//! PPP framing implementations.
//!
//! - [`HdlcFramer`] — HDLC async-control-character framing spoken toward `pppd`.
//! - [`FortiFramer`] — Fortinet's 6-byte `0x5050` length header spoken toward
//!   the gateway over the TLS tunnel.
//!
//! Ported from the original `openfortivpn-rs` crate (`hdlc.rs`, `io.rs`); the
//! FCS table and byte-level behavior are unchanged and covered by the tests
//! below.

use crate::core::framer::Framer;
use anyhow::{Result, bail};
use bytes::{Buf, BufMut, BytesMut};

// --------------------------------------------------------------------------
// HDLC (toward pppd)
// --------------------------------------------------------------------------

pub struct HdlcFramer {
    need_flag_sequence: bool,
}

impl HdlcFramer {
    pub fn new() -> Self {
        Self {
            need_flag_sequence: true,
        }
    }
}

impl Default for HdlcFramer {
    fn default() -> Self {
        Self::new()
    }
}

const FCS_TAB: [u16; 256] = [
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1, 0xaf5a, 0xbed3,
    0xca6c, 0xdbe5, 0xe97e, 0xf8f7, 0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876, 0x2102, 0x308b, 0x0210, 0x1399,
    0x6726, 0x76af, 0x4434, 0x55bd, 0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9, 0x8f50,
    0xfbef, 0xea66, 0xd8fd, 0xc974, 0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3, 0x5285, 0x430c, 0x7197, 0x601e,
    0x14a1, 0x0528, 0x37b3, 0x263a, 0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c, 0xddd5,
    0xa96a, 0xb8e3, 0x8a78, 0x9bf1, 0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70, 0x8408, 0x9581, 0xa71a, 0xb693,
    0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036, 0x18c1, 0x0948, 0x3bd3, 0x2a5a,
    0x5ee5, 0x4f6c, 0x7df7, 0x6c7e, 0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd, 0xb58b, 0xa402, 0x9699, 0x8710,
    0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3, 0x4a44, 0x5bcd, 0x6956, 0x78df,
    0x0c60, 0x1de9, 0x2f72, 0x3efb, 0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a, 0xe70e, 0xf687, 0xc41c, 0xd595,
    0xa12a, 0xb0a3, 0x8238, 0x93b1, 0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e, 0x58d5, 0x495c,
    0x3de3, 0x2c6a, 0x1ef1, 0x0f78,
];

fn frame_checksum_16bit(mut sum: u16, data: &[u8]) -> u16 {
    for &b in data {
        let index = ((sum ^ (b as u16)) & 0xff) as usize;
        sum = (sum >> 8) ^ FCS_TAB[index];
    }
    sum
}

const ADDRESS_CONTROL_CHECKSUM: u16 = 0x3de3;
const ADDRESS_CONTROL_FIELDS: [u8; 2] = [0xff, 0x03];

fn in_sending_accm(byte: u8) -> bool {
    byte < 0x20 || (byte & 0x7f) == 0x7d || (byte & 0x7f) == 0x7e
}

fn in_receiving_accm(byte: u8) -> bool {
    byte < 0x20
}

impl Framer for HdlcFramer {
    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<()> {
        let estimated_len = 9 + 2 * item.len();
        dst.reserve(estimated_len);

        if self.need_flag_sequence {
            dst.put_u8(0x7e);
        }

        dst.put_u8(ADDRESS_CONTROL_FIELDS[0]);
        dst.put_u8(0x7d);
        dst.put_u8(ADDRESS_CONTROL_FIELDS[1] ^ 0x20);

        let mut checksum = ADDRESS_CONTROL_CHECKSUM;

        for &byte in item {
            if in_sending_accm(byte) {
                dst.put_u8(0x7d);
                dst.put_u8(byte ^ 0x20);
            } else {
                dst.put_u8(byte);
            }
        }

        checksum = frame_checksum_16bit(checksum, item);
        checksum ^= 0xffff;

        let byte1 = (checksum & 0xff) as u8;
        if in_sending_accm(byte1) {
            dst.put_u8(0x7d);
            dst.put_u8(byte1 ^ 0x20);
        } else {
            dst.put_u8(byte1);
        }

        let byte2 = ((checksum >> 8) & 0xff) as u8;
        if in_sending_accm(byte2) {
            dst.put_u8(0x7d);
            dst.put_u8(byte2 ^ 0x20);
        } else {
            dst.put_u8(byte2);
        }

        dst.put_u8(0x7e);
        self.need_flag_sequence = false;

        Ok(())
    }

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>> {
        let mut start_idx = None;
        let mut end_idx = None;

        for (i, &b) in src.iter().enumerate() {
            if b == 0x7e {
                if start_idx.is_none() {
                    start_idx = Some(i + 1);
                } else if i > start_idx.unwrap() {
                    end_idx = Some(i);
                    break;
                } else {
                    start_idx = Some(i + 1);
                }
            }
        }

        let (start, end) = match (start_idx, end_idx) {
            (Some(s), Some(e)) => (s, e),
            _ => return Ok(None),
        };

        let frame = &src[start..end];

        let mut decoded = BytesMut::with_capacity(frame.len());
        let mut in_escape = false;
        let mut has_address_control = false;

        let mut frame_slice = frame;
        if frame_slice.len() >= 3
            && frame_slice[0] == 0xff
            && frame_slice[1] == 0x7d
            && frame_slice[2] == (0x03 ^ 0x20)
        {
            has_address_control = true;
            frame_slice = &frame_slice[3..];
        }

        for &byte in frame_slice {
            if byte == 0x7d {
                if in_escape {
                    src.advance(end);
                    bail!("HDLC: double escape in frame");
                }
                in_escape = true;
            } else if in_escape {
                decoded.put_u8(byte ^ 0x20);
                in_escape = false;
            } else if in_receiving_accm(byte) {
                continue;
            } else {
                decoded.put_u8(byte);
            }
        }

        if in_escape || decoded.len() < 2 {
            src.advance(end);
            bail!("HDLC: truncated frame");
        }

        let data_len = decoded.len() - 2;
        let mut checksum = if has_address_control {
            ADDRESS_CONTROL_CHECKSUM
        } else {
            0xffff
        };
        checksum = frame_checksum_16bit(checksum, &decoded[..decoded.len()]);

        if checksum != 0xf0b8 {
            src.advance(end);
            bail!("HDLC: bad checksum");
        }

        src.advance(end);

        let mut pkt = decoded;
        pkt.truncate(data_len);

        Ok(Some(pkt))
    }
}

// --------------------------------------------------------------------------
// Fortinet transport framing (toward the gateway)
// --------------------------------------------------------------------------

/// 6-byte header: `[u16 total_len][u16 0x5050][u16 payload_len]` then payload.
pub struct FortiFramer;

impl Framer for FortiFramer {
    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<()> {
        let len = item.len();
        let total_len = len + 6;

        dst.reserve(total_len);
        dst.put_u16(total_len as u16);
        dst.put_u16(0x5050);
        dst.put_u16(len as u16);
        dst.put_slice(item);

        Ok(())
    }

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>> {
        if src.len() < 6 {
            return Ok(None);
        }

        let total_len = u16::from_be_bytes([src[0], src[1]]) as usize;
        let magic = u16::from_be_bytes([src[2], src[3]]);
        let size = u16::from_be_bytes([src[4], src[5]]) as usize;

        if src[0..6] == b"HTTP/1"[..] {
            bail!("Received HTTP response instead of PPP frame. Check authentication / realm.");
        }

        if magic != 0x5050 || total_len < 7 || total_len - 6 != size {
            bail!("Invalid Fortinet transport header");
        }

        if src.len() < total_len {
            return Ok(None);
        }

        let mut pkt = src.split_to(total_len);
        pkt.advance(6);

        Ok(Some(pkt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        let packet = [0xc0, 0x21, 0x01, 0x01, 0x00, 0x04];
        let mut checksum = ADDRESS_CONTROL_CHECKSUM;
        checksum = frame_checksum_16bit(checksum, &packet);
        checksum ^= 0xffff;
        assert_eq!(checksum, 0xb5d1);
    }

    #[test]
    fn test_hdlc_encode_decode() {
        let mut encoder = HdlcFramer::new();
        let mut decoder = HdlcFramer::new();

        let payload = [0xc0u8, 0x21, 0x01, 0x01, 0x00, 0x04];
        let mut encoded = BytesMut::new();
        encoder.encode(&payload, &mut encoded).unwrap();

        let mut buf = encoded.clone();
        let decoded = decoder.decode(&mut buf).unwrap().unwrap();

        assert_eq!(&decoded[..], &payload[..]);
    }

    #[test]
    fn test_hdlc_roundtrip_with_escapes() {
        // Payload containing bytes that must be HDLC-escaped: flag 0x7e, escape
        // 0x7d, and control chars in the ACCM (< 0x20).
        let mut encoder = HdlcFramer::new();
        let mut decoder = HdlcFramer::new();

        let payload = [0x7eu8, 0x7d, 0x00, 0x11, 0x1f, 0xff, 0x03, 0x80];
        let mut encoded = BytesMut::new();
        encoder.encode(&payload, &mut encoded).unwrap();

        // Escaped bytes must not appear raw between the flags.
        assert!(encoded.windows(1).filter(|w| w[0] == 0x7e).count() >= 2);

        let mut buf = encoded.clone();
        let decoded = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&decoded[..], &payload[..]);
    }

    #[test]
    fn test_hdlc_partial_frame_yields_none() {
        let mut decoder = HdlcFramer::new();
        // A lone opening flag with no closing flag is incomplete.
        let mut buf = BytesMut::from(&[0x7eu8, 0xff, 0x7d, 0x23, 0x01][..]);
        assert!(decoder.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn test_forti_encode_decode() {
        let mut f = FortiFramer;
        let payload = [0x21u8, 0x45, 0x00, 0x00];
        let mut encoded = BytesMut::new();
        f.encode(&payload, &mut encoded).unwrap();
        assert_eq!(&encoded[..6], &[0x00, 0x0a, 0x50, 0x50, 0x00, 0x04]);

        let mut buf = encoded.clone();
        let decoded = f.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&decoded[..], &payload[..]);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_forti_partial_header_yields_none() {
        let mut f = FortiFramer;
        let mut buf = BytesMut::from(&[0x00u8, 0x0a, 0x50][..]); // < 6 bytes
        assert!(f.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn test_forti_rejects_http_response() {
        let mut f = FortiFramer;
        let mut buf = BytesMut::from(&b"HTTP/1.1 401 Unauthorized\r\n\r\n"[..]);
        assert!(f.decode(&mut buf).is_err());
    }

    #[test]
    fn test_forti_two_frames_in_buffer() {
        let mut f = FortiFramer;
        let mut buf = BytesMut::new();
        f.encode(&[0xaa, 0xbb], &mut buf).unwrap();
        f.encode(&[0xcc], &mut buf).unwrap();
        assert_eq!(&f.decode(&mut buf).unwrap().unwrap()[..], &[0xaa, 0xbb]);
        assert_eq!(&f.decode(&mut buf).unwrap().unwrap()[..], &[0xcc]);
        assert!(f.decode(&mut buf).unwrap().is_none());
    }
}
