// SPDX-License-Identifier: GPL-3.0-or-later
//! Parse the Fortinet `fortisslvpn_xml` config into provider-neutral
//! [`TunnelParams`].

use crate::core::provider::{Route, TunnelParams};
use anyhow::{Context, Result};
use roxmltree::Document;
use std::net::Ipv4Addr;

/// Convert a dotted-decimal netmask to a CIDR prefix length.
pub fn mask_to_prefix(mask: &str) -> Result<u8> {
    let octets: Vec<u8> = mask
        .split('.')
        .map(|s| s.parse::<u8>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid netmask format")?;

    if octets.len() != 4 {
        anyhow::bail!("Netmask must have four octets");
    }

    let mask_u32 = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);

    if mask_u32 != 0 && (mask_u32 | (mask_u32 - 1)) != 0xFFFF_FFFF {
        anyhow::bail!("Non-contiguous netmask: {}", mask);
    }

    Ok(mask_u32.count_ones() as u8)
}

pub fn parse_tunnel_params(xml: &str) -> Result<TunnelParams> {
    let doc = Document::parse(xml).context("Failed to parse VPN config XML")?;
    let mut params = TunnelParams::default();

    for dns_node in doc.descendants().filter(|n| n.has_tag_name("dns")) {
        if let Some(ip) = dns_node.attribute("ip")
            && let Ok(addr) = ip.parse::<Ipv4Addr>()
        {
            params.dns.push(addr);
        }
        if params.dns_suffix.is_none()
            && let Some(domain) = dns_node.attribute("domain")
            && !domain.is_empty()
        {
            params.dns_suffix = Some(domain.to_string());
        }
    }

    if let Some(node) = doc.descendants().find(|n| n.has_tag_name("assigned-addr"))
        && let Some(ip) = node.attribute("ipv4")
        && let Ok(addr) = ip.parse::<Ipv4Addr>()
    {
        params.assigned_addr = Some(addr);
    }

    if let Some(split) = doc
        .descendants()
        .find(|n| n.has_tag_name("split-tunnel-info"))
    {
        for addr_node in split.children().filter(|c| c.has_tag_name("addr")) {
            if let (Some(ip), Some(mask)) = (addr_node.attribute("ip"), addr_node.attribute("mask"))
                && let Ok(dest) = ip.parse::<Ipv4Addr>()
            {
                let prefix = mask_to_prefix(mask)?;
                params.routes.push(Route { dest, prefix });
            }
        }
    }

    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "<?xml version='1.0' encoding='utf-8'?><sslvpn-tunnel ver='1' patch='1'><ipv4><dns ip='2.2.2.2' domain='corp.example' /><dns ip='8.8.8.8' /><assigned-addr ipv4='123.123.123.123' /><split-tunnel-info><addr ip='172.16.0.0' mask='255.240.0.0' /><addr ip='10.0.0.0' mask='255.0.0.0' /></split-tunnel-info></ipv4></sslvpn-tunnel>";

    #[test]
    fn test_parse() {
        let p = parse_tunnel_params(SAMPLE).unwrap();
        assert_eq!(
            p.dns,
            vec![
                "2.2.2.2".parse::<Ipv4Addr>().unwrap(),
                "8.8.8.8".parse().unwrap()
            ]
        );
        assert_eq!(p.dns_suffix.as_deref(), Some("corp.example"));
        assert_eq!(p.assigned_addr, Some("123.123.123.123".parse().unwrap()));
        assert_eq!(
            p.routes,
            vec![
                Route {
                    dest: "172.16.0.0".parse().unwrap(),
                    prefix: 12
                },
                Route {
                    dest: "10.0.0.0".parse().unwrap(),
                    prefix: 8
                },
            ]
        );
    }

    #[test]
    fn test_mask_to_prefix() {
        assert_eq!(mask_to_prefix("255.255.255.0").unwrap(), 24);
        assert_eq!(mask_to_prefix("255.240.0.0").unwrap(), 12);
        assert_eq!(mask_to_prefix("0.0.0.0").unwrap(), 0);
        assert_eq!(mask_to_prefix("255.255.255.255").unwrap(), 32);
        assert!(mask_to_prefix("255.0.255.0").is_err());
        assert!(mask_to_prefix("255.255.255").is_err());
    }
}
