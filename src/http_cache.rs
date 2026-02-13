use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

#[derive(Serialize, Deserialize)]
struct CachedResponse {
    body: String,
    cached_at: u64,
    ttl_seconds: u64,
}

impl CachedResponse {
    fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.cached_at + self.ttl_seconds
    }
}

pub struct HttpCache {
    cache_dir: PathBuf,
    ttl_seconds: u64,
}

impl HttpCache {
    pub fn new(app_name: &str, ttl_seconds: u64) -> anyhow::Result<Self> {
        let cache_dir = dirs::cache_dir()
            .ok_or(anyhow::anyhow!("Could not determine cache directory"))?
            .join(app_name);

        std::fs::create_dir_all(&cache_dir)?;

        Ok(Self {
            cache_dir,
            ttl_seconds,
        })
    }

    pub fn cache_path(&self, url: &Url) -> PathBuf {
        let cache_key = format!("{:x}", md5::compute(url.as_str()));
        self.cache_dir.join(format!("{}.json", cache_key))
    }

    pub fn get(&self, url: &Url) -> Option<String> {
        let cache_file = self.cache_path(url);

        let cached_data = std::fs::read_to_string(&cache_file).ok()?;
        let cached: CachedResponse = serde_json::from_str(&cached_data).ok()?;

        if cached.is_expired() {
            return None;
        }

        Some(cached.body)
    }

    pub fn set(&self, url: &Url, body: String) {
        let cached = CachedResponse {
            body,
            cached_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl_seconds: self.ttl_seconds,
        };

        if let Ok(json) = serde_json::to_string(&cached) {
            let cache_file = self.cache_path(url);
            let _ = std::fs::write(cache_file, json);
        }
    }

    pub fn clear_all(&self) -> std::io::Result<()> {
        if self.cache_dir.exists() {
            std::fs::remove_dir_all(&self.cache_dir)?;
        }
        Ok(())
    }

    pub async fn get_or_fetch<T>(&self, client: &Client, url: &Url) -> anyhow::Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        // Try cache first - returns the raw JSON string
        let body = if let Some(cached_body) = self.get(url) {
            cached_body
        } else {
            // Fetch from network
            let response = client.get(url.clone()).send().await?.error_for_status()?;

            let body = response.text().await?;

            // Cache the response
            self.set(url, body.clone());

            body
        };

        // Deserialize once at the end
        Ok(serde_json::from_str(&body)?)
    }
}
