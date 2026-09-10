// ==============================================================================
// mail.rs - spoke-mail-relay client
// ==============================================================================
// Description: POSTs to spoke-mail-relay's `/send` (see
//              spoke-mail-relay/mail_relay/src/mail_relay/main.py
//              SendRequest) — {to, subject, body_text, body_html}. The relay
//              owns the From address (MAIL_FROM_EMAIL, its own env), so this
//              client never sets one. Trait-based like anthropic.rs's
//              Transport (spec §8's mocked-transport pattern) so mail
//              delivery is exercised in tests without a live relay.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct SendRequest {
    pub to: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: String,
}

#[derive(Debug, Deserialize)]
struct SendResponse {
    status: String,
}

#[async_trait]
pub trait MailTransport: Send + Sync {
    async fn send(&self, req: &SendRequest) -> anyhow::Result<()>;
}

pub struct RelayTransport {
    http: reqwest::Client,
    base_url: String,
}

impl RelayTransport {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: format!("http://{host}:{port}"),
        }
    }
}

#[async_trait]
impl MailTransport for RelayTransport {
    async fn send(&self, req: &SendRequest) -> anyhow::Result<()> {
        let response = self
            .http
            .post(format!("{}/send", self.base_url))
            .json(req)
            .timeout(Duration::from_secs(30))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("mail relay returned {status}: {body}");
        }

        let parsed: SendResponse = response.json().await?;
        if parsed.status != "sent" {
            anyhow::bail!("mail relay reported status={:?}", parsed.status);
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::Mutex;

    pub struct MockMailTransport {
        pub sent: Mutex<Vec<SendRequest>>,
        pub fail: bool,
    }

    impl MockMailTransport {
        pub fn new() -> Self {
            Self { sent: Mutex::new(Vec::new()), fail: false }
        }

        pub fn failing() -> Self {
            Self { sent: Mutex::new(Vec::new()), fail: true }
        }
    }

    #[async_trait]
    impl MailTransport for MockMailTransport {
        async fn send(&self, req: &SendRequest) -> anyhow::Result<()> {
            if self.fail {
                anyhow::bail!("mock relay failure");
            }
            self.sent.lock().unwrap().push(SendRequest {
                to: req.to.clone(),
                subject: req.subject.clone(),
                body_text: req.body_text.clone(),
                body_html: req.body_html.clone(),
            });
            Ok(())
        }
    }
}
