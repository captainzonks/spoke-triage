// ==============================================================================
// anthropic.rs - Anthropic Messages API client
// ==============================================================================
// Description: Forced tool-use + strict schema (spec §5), prompt caching on
//              the system block (spec §9), exponential backoff with jitter
//              honoring retry-after on 429/5xx (spec §9). Wire shapes and
//              cache-write multipliers verified live against
//              platform.claude.com/docs on 2026-09-09 per spec §11 — no
//              official Anthropic Rust SDK exists, so this is reqwest +
//              serde_json against the documented JSON contract directly.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

pub const ANTHROPIC_VERSION: &str = "2023-06-01";
const MAX_RETRIES: u32 = 5;

#[derive(Debug, Serialize)]
pub struct MessagesRequest {
    pub model: String,
    pub max_tokens: u32,
    pub system: Vec<SystemBlock>,
    pub messages: Vec<MessageParam>,
    pub tools: Vec<Value>,
    pub tool_choice: ToolChoice,
}

#[derive(Debug, Serialize)]
pub struct SystemBlock {
    #[serde(rename = "type")]
    pub block_type: &'static str,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

#[derive(Debug, Serialize)]
pub struct CacheControl {
    #[serde(rename = "type")]
    pub control_type: &'static str,
}

#[derive(Debug, Serialize)]
pub struct MessageParam {
    pub role: &'static str,
    pub content: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum ToolChoice {
    #[serde(rename = "tool")]
    Tool { name: String },
}

#[derive(Debug, Deserialize)]
pub struct MessagesResponse {
    pub content: Vec<ContentBlock>,
    pub usage: Usage,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text {
        #[allow(dead_code)]
        text: String,
    },
    ToolUse { name: String, input: Value },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize, Default)]
pub struct Usage {
    pub input_tokens: i64,
    pub output_tokens: i64,
    #[serde(default)]
    pub cache_creation_input_tokens: i64,
    #[serde(default)]
    pub cache_read_input_tokens: i64,
}

/// Trait-based so tests never make a paid API call (spec §8).
#[async_trait]
pub trait Transport: Send + Sync {
    async fn create_message(&self, request: &MessagesRequest) -> anyhow::Result<MessagesResponse>;
}

pub struct AnthropicTransport {
    http: reqwest::Client,
    api_key: String,
}

impl AnthropicTransport {
    pub fn new(api_key: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key,
        }
    }
}

#[async_trait]
impl Transport for AnthropicTransport {
    async fn create_message(&self, request: &MessagesRequest) -> anyhow::Result<MessagesResponse> {
        let mut attempt = 0u32;
        loop {
            let response = self
                .http
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", ANTHROPIC_VERSION)
                .header("content-type", "application/json")
                .json(request)
                .timeout(Duration::from_secs(120))
                .send()
                .await?;

            let status = response.status();
            if status.is_success() {
                return Ok(response.json::<MessagesResponse>().await?);
            }

            let retryable = status.as_u16() == 429 || status.is_server_error();
            if !retryable || attempt >= MAX_RETRIES {
                let body = response.text().await.unwrap_or_default();
                anyhow::bail!("Anthropic API error {status}: {body}");
            }

            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs);

            let backoff = retry_after.unwrap_or_else(|| backoff_with_jitter(attempt));
            tokio::time::sleep(backoff).await;
            attempt += 1;
        }
    }
}

fn backoff_with_jitter(attempt: u32) -> Duration {
    use rand::Rng;
    let base_secs = 2u64.saturating_pow(attempt).min(60);
    let jitter_ms = rand::thread_rng().gen_range(0..1000);
    Duration::from_secs(base_secs) + Duration::from_millis(jitter_ms)
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::Mutex;

    /// Records every request it receives and always returns the same
    /// canned response — for tests that need to inspect what was sent
    /// (e.g. that benign-verdict templates were excluded from the prompt).
    pub struct MockTransport {
        pub response: MessagesResponse,
        pub requests: Mutex<Vec<MessagesRequest>>,
    }

    impl MockTransport {
        pub fn new(response: MessagesResponse) -> Self {
            Self {
                response,
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn create_message(&self, request: &MessagesRequest) -> anyhow::Result<MessagesResponse> {
            self.requests.lock().unwrap().push(MessagesRequest {
                model: request.model.clone(),
                max_tokens: request.max_tokens,
                system: request
                    .system
                    .iter()
                    .map(|s| SystemBlock {
                        block_type: s.block_type,
                        text: s.text.clone(),
                        cache_control: s.cache_control.as_ref().map(|c| CacheControl { control_type: c.control_type }),
                    })
                    .collect(),
                messages: request
                    .messages
                    .iter()
                    .map(|m| MessageParam { role: m.role, content: m.content.clone() })
                    .collect(),
                tools: request.tools.clone(),
                tool_choice: match &request.tool_choice {
                    ToolChoice::Tool { name } => ToolChoice::Tool { name: name.clone() },
                },
            });
            Ok(MessagesResponse {
                content: self.response.content.iter().map(clone_block).collect(),
                usage: Usage {
                    input_tokens: self.response.usage.input_tokens,
                    output_tokens: self.response.usage.output_tokens,
                    cache_creation_input_tokens: self.response.usage.cache_creation_input_tokens,
                    cache_read_input_tokens: self.response.usage.cache_read_input_tokens,
                },
            })
        }
    }

    fn clone_block(b: &ContentBlock) -> ContentBlock {
        match b {
            ContentBlock::Text { text } => ContentBlock::Text { text: text.clone() },
            ContentBlock::ToolUse { name, input } => ContentBlock::ToolUse { name: name.clone(), input: input.clone() },
            ContentBlock::Other => ContentBlock::Other,
        }
    }
}
