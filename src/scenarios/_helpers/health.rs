use std::time::{Duration, Instant};

pub(crate) async fn wait_for_health(base_url: &str, timeout: Duration) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };
    let url = format!("{base_url}/health");
    let cutoff = Instant::now() + timeout;
    while Instant::now() < cutoff {
        if let Ok(response) = client.get(&url).send().await
            && response.status().is_success()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}
