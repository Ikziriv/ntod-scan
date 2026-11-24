//! AI layer: natural-language → Filter, flow summarizer.
//! Local-first via Ollama; rule-based fallback needs no LLM at all.

use std::time::Duration;

use async_trait::async_trait;
use ntod_core::{Filter, Proto};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("could not parse a filter from the model output")]
    Parse,
}

#[async_trait]
pub trait AiBackend: Send + Sync {
    async fn complete(&self, prompt: &str) -> Result<String, Error>;
}

/// Ollama at `base` (default http://127.0.0.1:11434), POST /api/generate.
pub struct Ollama {
    pub base: String,
    pub model: String,
    http: reqwest::Client,
}

impl Ollama {
    pub fn new(base: impl Into<String>, model: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            model: model.into(),
            http,
        }
    }

    /// Build from `$NTOD_AI_BASE` / `$NTOD_AI_MODEL` with local Ollama defaults.
    pub fn from_env() -> Self {
        let base =
            std::env::var("NTOD_AI_BASE").unwrap_or_else(|_| "http://127.0.0.1:11434".into());
        let model = std::env::var("NTOD_AI_MODEL").unwrap_or_else(|_| "llama3.2".into());
        Self::new(base, model)
    }
}

#[async_trait]
impl AiBackend for Ollama {
    async fn complete(&self, prompt: &str) -> Result<String, Error> {
        let resp: serde_json::Value = self
            .http
            .post(format!("{}/api/generate", self.base))
            .json(&serde_json::json!({
                "model": self.model,
                "prompt": prompt,
                "stream": false
            }))
            .send()
            .await?
            .json()
            .await?;
        Ok(resp["response"].as_str().unwrap_or_default().to_string())
    }
}

/// Parse a filter out of model output — first `{...}` block must be
/// valid JSON matching Filter; otherwise fall back to rules.
fn filter_from_text(text: &str) -> Option<Filter> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    serde_json::from_str(&text[start..=end]).ok()
}

const FILTER_PROMPT: &str = "Convert this request into a JSON packet filter \
of shape {\"proto\": \"Tcp\"|\"Udp\"|\"Icmp\"|null, \"src\": \"<ip>\"|null, \
\"dst\": \"<ip>\"|null, \"port\": <number>|null}. Output ONLY the JSON.";

/// NL → Filter via backend if present, else deterministic rules.
/// Never fails hard — worst case returns an empty (match-all) Filter.
pub async fn nl_to_filter(q: &str, backend: Option<&dyn AiBackend>) -> Filter {
    if let Some(b) = backend
        && let Ok(text) = b
            .complete(&format!("{FILTER_PROMPT}\n\nRequest: {q}"))
            .await
        && let Some(f) = filter_from_text(&text)
    {
        return f;
    }
    rules_filter(q)
}

/// Rule fallback: keyword → Filter. Covers the common cases offline.
pub fn rules_filter(q: &str) -> Filter {
    let q = q.to_lowercase();
    let proto = if q.contains("tcp") {
        Some(Proto::Tcp)
    } else if q.contains("udp") || q.contains("dns") {
        Some(Proto::Udp)
    } else if q.contains("icmp") || q.contains("ping") {
        Some(Proto::Icmp)
    } else {
        None
    };
    let mut f = Filter {
        proto,
        port: q.contains("dns").then_some(53),
        ..Filter::default()
    };
    let words: Vec<&str> = q.split_whitespace().collect();
    for (i, &w) in words.iter().enumerate() {
        match w {
            "port" if i + 1 < words.len() => {
                f.port = words[i + 1].parse().ok();
            }
            "from" | "src" if i + 1 < words.len() => {
                f.src = words[i + 1].parse().ok();
            }
            "to" | "dst" | "destination" if i + 1 < words.len() => {
                f.dst = words[i + 1].parse().ok();
            }
            _ => {
                if let Ok(port) = w.parse::<u16>() {
                    f.port = Some(port);
                }
            }
        }
    }
    f
}

/// Summarize flow aggregates (never payloads) via the backend.
pub async fn summarize(what: &str, facts: &str, backend: &dyn AiBackend) -> Result<String, Error> {
    backend
        .complete(&format!(
            "You are a network analyst. Summarize these {what} facts in 3 short \
             sentences for a security-conscious user. Flag anything unusual.\n\n{facts}"
        ))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn rules_dns() {
        let f = rules_filter("show dns traffic");
        assert_eq!(f.proto, Some(Proto::Udp));
        assert_eq!(f.port, Some(53));
    }

    #[test]
    fn rules_tcp_from_ip() {
        let f = rules_filter("tcp to port 443 from 10.0.0.5");
        assert_eq!(f.proto, Some(Proto::Tcp));
        assert_eq!(f.port, Some(443));
        assert_eq!(f.src, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
    }

    #[test]
    fn filter_from_text_extracts_json() {
        let f = filter_from_text(
            "here you go {\"proto\":\"Tcp\",\"src\":null,\"dst\":null,\"port\":80} done",
        );
        assert!(f.is_some());
        assert_eq!(f.unwrap().port, Some(80));
        assert!(filter_from_text("no json").is_none());
    }
}
