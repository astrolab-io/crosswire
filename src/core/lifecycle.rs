// SPDX-License-Identifier: GPL-3.0-or-later
//! Cooperative shutdown signaling shared across the engine and its io tasks.

use tokio::sync::watch;

/// A cloneable handle that resolves once shutdown has been requested.
#[derive(Clone)]
pub struct Shutdown(watch::Receiver<bool>);

impl Shutdown {
    pub fn is_triggered(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolve when shutdown is requested (or the controller is dropped).
    pub async fn wait(&mut self) {
        while !*self.0.borrow() {
            if self.0.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Triggers shutdown for all associated [`Shutdown`] handles.
pub struct ShutdownController {
    tx: watch::Sender<bool>,
}

impl ShutdownController {
    pub fn new() -> (Self, Shutdown) {
        let (tx, rx) = watch::channel(false);
        (Self { tx }, Shutdown(rx))
    }

    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }
}
