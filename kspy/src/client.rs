use serde::{Deserialize, Serialize};
use tokio::{fs::File, io::AsyncReadExt};
use uuid::Uuid;

const GRADIO_SERVER_PREDICT_URL: &str = "http://192.168.8.121:8333/predict";

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    id: String,
    path: String,
    content: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    id: String,
    result: String,
}

pub async fn setup_connection() -> anyhow::Result<reqwest::Client> {
    let client = reqwest::Client::new();
    Ok(client)
}

pub async fn send_request(path: String, client: &reqwest::Client) -> anyhow::Result<Response> {
    let id = Uuid::new_v4().to_string();

    let mut file = File::open(&path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;

    let req = Request {
        id,
        path: path.clone(),
        content: contents,
    };

    // 设置 2 秒超时
    let resp = tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        client.post(GRADIO_SERVER_PREDICT_URL).json(&req).send(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("request timed out"))??;

    let resp: Response = resp.json().await?;
    log::debug!("Response: {:?}", resp);
    if resp.result == "恶意 WebShell" {
        log::error!("[!] found WebShell: {}", path);
        log::error!("do something ..");
    }
    Ok(resp)
}
