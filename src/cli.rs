// SPDX-License-Identifier: GPL-3.0-or-later
//! Command-line and config-file parsing (provider-neutral core options).

use anyhow::{Context, Result};
use clap::{Parser, builder::BoolishValueParser};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug, Clone)]
#[command(name = "crosswire")]
#[command(about = "A generic PPP-over-TLS VPN client (FortiGate provider)", long_about = None)]
pub struct Args {
    #[arg(
        short = 'c',
        long = "config",
        default_value = "/etc/crosswire/config",
        value_hint = clap::ValueHint::FilePath,
        help = "Specify a custom configuration file."
    )]
    pub config_file: Option<PathBuf>,

    #[command(flatten)]
    pub config: Config,
}

#[derive(Parser, Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    #[arg(value_hint = clap::ValueHint::Hostname)]
    pub host: String,

    #[arg(long, default_value_t = default_port())]
    #[serde(default = "default_port")]
    pub port: u16,

    #[arg(short = 'u', long = "username", help = "VPN account username.")]
    pub username: Option<String>,

    #[arg(short = 'p', long = "password", help = "VPN account password.")]
    pub password: Option<String>,

    #[arg(long = "realm", help = "Authentication realm.")]
    pub realm: Option<String>,

    #[arg(
        long = "saml-login",
        value_name = "PORT",
        default_missing_value = "8020",
        num_args = 0..=1,
        help = "Run a local http server (default port 8020) to handle SAML login."
    )]
    pub saml_port: Option<u16>,

    #[arg(
        long,
        help = "Supply a valid session cookie directly instead of credentials."
    )]
    pub cookie: Option<String>,

    #[arg(long, help = "Read the session cookie from standard input.")]
    pub cookie_on_stdin: bool,

    #[arg(
        long,
        help = "Trust the gateway by its X509 SHA256 digest (repeatable)."
    )]
    pub trusted_cert: Vec<String>,

    #[arg(long, value_hint = clap::ValueHint::FilePath, help = "PEM CA bundle used to verify the gateway.")]
    pub ca_file: Option<PathBuf>,

    #[arg(short = 'o', long = "otp", help = "One-time password (for 2FA).")]
    pub otp: Option<String>,

    #[arg(long, help = "String the OTP challenge prompt begins with.")]
    pub otp_prompt: Option<String>,

    #[arg(
        long,
        default_value_t = 0,
        help = "Seconds to wait before sending the OTP."
    )]
    #[serde(default)]
    pub otp_delay: u64,

    #[arg(long, help = "Disable FortiToken Mobile push; force OTP entry.")]
    pub no_ftm_push: bool,

    #[arg(long, value_hint = clap::ValueHint::ExecutablePath, help = "Use this pinentry program to obtain secrets instead of prompting.")]
    pub pinentry: Option<PathBuf>,

    #[cfg_attr(feature = "pkcs11", arg(long, value_hint = clap::ValueHint::FilePath, help = "PEM client certificate for mutual TLS, or a pkcs11: URI."))]
    #[cfg_attr(not(feature = "pkcs11"), arg(long, value_hint = clap::ValueHint::FilePath, help = "PEM client certificate for mutual TLS."))]
    pub user_cert: Option<String>,

    #[cfg_attr(feature = "pkcs11", arg(long, value_hint = clap::ValueHint::FilePath, help = "PEM client private key, or a pkcs11: URI."))]
    #[cfg_attr(not(feature = "pkcs11"), arg(long, value_hint = clap::ValueHint::FilePath, help = "PEM client private key."))]
    pub user_key: Option<PathBuf>,

    #[arg(long, help = "Passphrase for the PEM client key.")]
    pub pem_passphrase: Option<String>,

    #[arg(
        long,
        value_name = "VERSION",
        default_value = "1.2",
        help = "Minimum TLS version: 1.0, 1.1, 1.2 or 1.3."
    )]
    #[serde(default = "default_min_tls")]
    pub min_tls: String,

    #[arg(long, help = "Explicit OpenSSL cipher list (TLS <= 1.2).")]
    pub cipher_list: Option<String>,

    #[arg(
        long,
        help = "Do not disable insecure TLS protocols/ciphers (@SECLEVEL=0)."
    )]
    pub insecure_ssl: bool,

    #[arg(
        long,
        default_value_t = 0,
        help = "Run persistently, reconnecting forever; wait N seconds between attempts (0 = disabled)."
    )]
    #[serde(default)]
    pub persistent: u64,

    #[arg(
        long,
        default_value = "true",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        help = "Configure IP routes through the VPN when the tunnel is up."
    )]
    #[serde(default = "default_true")]
    pub set_routes: bool,

    #[arg(
        long,
        default_value = "true",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        help = "Add the VPN's DNS servers to the system resolver when up."
    )]
    #[serde(default = "default_true")]
    pub set_dns: bool,

    #[arg(
        long,
        default_value = "true",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        help = "Assign the tunnel's IP address to the interface. Disable (--set-ip false) to let an external manager (e.g. pppd/NetworkManager) own it."
    )]
    #[serde(default = "default_true")]
    pub set_ip: bool,

    #[arg(
        long,
        help = "In full-tunnel mode, add 0.0.0.0/1 and 128.0.0.0/1 instead of replacing the default route (allows DHCP renewal)."
    )]
    pub half_internet_routes: bool,

    #[arg(
        long,
        help = "Use the resolvconf utility rather than editing resolv.conf directly."
    )]
    pub use_resolvconf: bool,

    #[arg(
        long,
        default_value = "false",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        help = "Ask the peer PPP server for DNS and let pppd rewrite /etc/resolv.conf."
    )]
    pub pppd_use_peerdns: bool,

    #[arg(long, value_hint = clap::ValueHint::FilePath, help = "Set pppd in debug mode and save its logs into <file>.")]
    pub pppd_log: Option<PathBuf>,

    #[arg(long, value_hint = clap::ValueHint::ExecutablePath, help = "Use the specified pppd plugin.")]
    pub pppd_plugin: Option<PathBuf>,

    #[arg(long, default_value = "ppp0", help = "Set the pppd interface name.")]
    #[serde(default = "default_ifname")]
    pub pppd_ifname: String,

    #[arg(long, help = "Extra parameter passed to the ip-up/ip-down scripts.")]
    pub pppd_ipparam: Option<String>,

    #[arg(long, help = "FreeBSD: system name in /etc/ppp/ppp.conf.")]
    pub pppd_system: Option<String>,

    #[arg(short, long, action = clap::ArgAction::Count, help = "Increase verbosity (repeatable).")]
    #[serde(default)]
    pub verbose: u8,
}

pub fn default_port() -> u16 {
    443
}
fn default_true() -> bool {
    true
}
fn default_ifname() -> String {
    "ppp0".to_string()
}
fn default_min_tls() -> String {
    "1.2".to_string()
}

impl Config {
    /// Merge values from a config file, without overriding anything already set
    /// on the CLI (CLI precedence).
    pub fn merge_from_path(&mut self, cfg_path: &Path) -> Result<()> {
        if !fs::exists(cfg_path)? {
            return Ok(());
        }

        let content = fs::read_to_string(cfg_path)
            .with_context(|| format!("Failed to read config file {:?}", cfg_path))?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches('"');
                match k {
                    "host" => {
                        if self.host.is_empty() {
                            self.host = v.to_string();
                        }
                    }
                    "port" => {
                        if self.port == 443 {
                            self.port = v.parse().unwrap_or(443);
                        }
                    }
                    "username" => {
                        self.username.get_or_insert_with(|| v.to_string());
                    }
                    "password" => {
                        self.password.get_or_insert_with(|| v.to_string());
                    }
                    "realm" => {
                        self.realm.get_or_insert_with(|| v.to_string());
                    }
                    "cookie" => {
                        self.cookie.get_or_insert_with(|| v.to_string());
                    }
                    "trusted-cert" => self.trusted_cert.push(v.to_string()),
                    "otp" => {
                        self.otp.get_or_insert_with(|| v.to_string());
                    }
                    "otp-prompt" => {
                        self.otp_prompt.get_or_insert_with(|| v.to_string());
                    }
                    "otp-delay" => {
                        if self.otp_delay == 0 {
                            self.otp_delay = v.parse().unwrap_or(0);
                        }
                    }
                    "no-ftm-push" => self.no_ftm_push = v != "0",
                    "min-tls" => {
                        if self.min_tls == "1.2" {
                            self.min_tls = v.to_string();
                        }
                    }
                    "cipher-list" => {
                        self.cipher_list.get_or_insert_with(|| v.to_string());
                    }
                    "insecure-ssl" => self.insecure_ssl = v != "0",
                    "user-cert" => {
                        self.user_cert.get_or_insert_with(|| v.to_string());
                    }
                    "user-key" => {
                        self.user_key.get_or_insert_with(|| v.into());
                    }
                    "set-routes" => self.set_routes = v != "0",
                    "half-internet-routes" => self.half_internet_routes = v != "0",
                    "set-dns" => self.set_dns = v != "0",
                    "set-ip" => self.set_ip = v != "0",
                    "use-resolvconf" => self.use_resolvconf = v != "0",
                    "pppd-use-peerdns" => self.pppd_use_peerdns = v != "0",
                    "persistent" => {
                        if self.persistent == 0 {
                            self.persistent = v.parse().unwrap_or(0);
                        }
                    }
                    "pppd-ifname" => self.pppd_ifname = v.to_string(),
                    _ => tracing::warn!("Ignoring unknown config key: {}", k),
                }
            }
        }

        // Split a "host:port" host field.
        if self.host.contains(':')
            && self.port == 443
            && let Some((h, p)) = self.host.clone().split_once(':')
        {
            self.host = h.to_string();
            if let Ok(port) = p.parse() {
                self.port = port;
            }
        }

        Ok(())
    }

    pub fn parse_and_merge() -> Result<Self> {
        let args = Args::parse();
        let mut config = args.config;
        if let Some(path) = &args.config_file {
            config.merge_from_path(path)?;
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_config(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[test]
    fn test_merge_from_path() {
        let config_content = "\nhost=vpn.test.com\nport=8443\nusername=testuser\nset-routes=0\ntrusted-cert=aa11\ntrusted-cert=bb22\n";
        let config_file = create_test_config(config_content);

        let mut config = Config {
            host: String::new(),
            port: 443,
            set_routes: true,
            ..Default::default()
        };

        config.merge_from_path(config_file.path()).unwrap();

        assert_eq!(config.host, "vpn.test.com");
        assert_eq!(config.port, 8443);
        assert_eq!(config.username, Some("testuser".to_string()));
        assert!(!config.set_routes);
        assert_eq!(config.trusted_cert, vec!["aa11", "bb22"]);
    }
}
