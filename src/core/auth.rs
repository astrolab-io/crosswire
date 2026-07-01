// SPDX-License-Identifier: GPL-3.0-or-later
//! Authentication strategy seam.
//!
//! Providers may compose one or more [`AuthMethod`]s (password, SAML, cookie,
//! client-cert, OTP). The FortiGate provider selects among them based on config.

use crate::core::provider::{ProviderContext, Session};
use anyhow::Result;
use async_trait::async_trait;

// Seam for M5 (client-cert/OTP strategies); not yet wired into a provider.
#[allow(dead_code)]
#[async_trait]
pub trait AuthMethod: Send + Sync {
    fn name(&self) -> &'static str;
    async fn authenticate(&self, ctx: &ProviderContext) -> Result<Session>;
}
