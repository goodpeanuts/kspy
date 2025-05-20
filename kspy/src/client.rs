use serde::{Deserialize, Serialize};
use tokio::{fs::File, io::AsyncReadExt};
use uuid::Uuid;

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

    let resp = client
        .post("http://192.168.8.121:8333/predict")
        .json(&req)
        .send()
        .await?;

    let resp: Response = resp.json().await?;
    log::debug!("Response: {:?}", resp);
    if resp.result == "恶意 WebShell" {
        log::error!("[!] found WebShell: {}", path);
        log::error!("do something ..");
    }
    Ok(resp)
}
