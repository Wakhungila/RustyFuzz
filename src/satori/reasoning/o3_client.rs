use crate::satori::cache::{CachedResponse, ResponseCache};
use crate::satori::error::SatoriResult;
use crate::satori::types::BudgetReport;
#[cfg(feature = "llm")]
use serde_json::json;
#[cfg(feature = "llm")]
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct O3Client {
    model: String,
    cache: ResponseCache,
}

impl O3Client {
    pub fn new(model: impl Into<String>, cache: ResponseCache) -> Self {
        Self {
            model: model.into(),
            cache,
        }
    }

    pub async fn complete_json(&self, prompt: &str) -> SatoriResult<(String, bool)> {
        let key = ResponseCache::key(&self.model, prompt);
        if let Some(cached) = self.cache.get(&key)? {
            return Ok((cached.response_text, true));
        }
        let response = complete_json_impl(&self.model, prompt).await?;
        self.cache.put(&CachedResponse {
            prompt_hash: key,
            model: self.model.clone(),
            response_text: response.clone(),
        })?;
        Ok((response, false))
    }
}

#[cfg(feature = "llm")]
async fn complete_json_impl(model: &str, prompt: &str) -> SatoriResult<String> {
    let api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| anyhow::anyhow!("OPENAI_API_KEY is required for Satori o3 calls"))?;
    let client = reqwest::Client::new();
    let body = json!({
        "model": model,
        "input": prompt,
        "text": { "format": { "type": "json_object" } }
    });
    let mut last_error = None;
    for attempt in 0..3 {
        let response = client
            .post("https://api.openai.com/v1/responses")
            .bearer_auth(&api_key)
            .json(&body)
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => {
                let value: serde_json::Value = response.json().await?;
                return extract_response_text(&value);
            }
            Ok(response) => {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                last_error = Some(anyhow::anyhow!("OpenAI response error {status}: {text}"));
            }
            Err(err) => last_error = Some(anyhow::anyhow!("OpenAI request failed: {err}")),
        }
        if attempt < 2 {
            tokio::time::sleep(Duration::from_millis(350 * (attempt + 1))).await;
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("OpenAI request failed")))
}

#[cfg(not(feature = "llm"))]
async fn complete_json_impl(_model: &str, _prompt: &str) -> SatoriResult<String> {
    Err(crate::satori::error::llm_feature_required())
}

#[cfg(feature = "llm")]
fn extract_response_text(value: &serde_json::Value) -> SatoriResult<String> {
    if let Some(text) = value.get("output_text").and_then(|v| v.as_str()) {
        return Ok(text.to_string());
    }
    if let Some(items) = value.get("output").and_then(|v| v.as_array()) {
        let mut text = String::new();
        for item in items {
            if let Some(content) = item.get("content").and_then(|v| v.as_array()) {
                for part in content {
                    if let Some(part_text) = part.get("text").and_then(|v| v.as_str()) {
                        text.push_str(part_text);
                    }
                }
            }
        }
        if !text.trim().is_empty() {
            return Ok(text);
        }
    }
    Err(anyhow::anyhow!(
        "OpenAI response did not contain text output"
    ))
}

#[allow(dead_code)]
pub fn empty_budget_report() -> BudgetReport {
    BudgetReport::default()
}

#[cfg(all(test, feature = "llm"))]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_o3_client_live() {
        let client = O3Client::new("o3", ResponseCache::new("satori/cache/test"));
        let result = client
            .complete_json("{\"task\":\"return {\\\"ok\\\":true}\"}")
            .await;
        assert!(result.is_ok());
    }
}
