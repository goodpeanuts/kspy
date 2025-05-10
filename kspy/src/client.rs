use std::sync::Arc;

use dashmap::DashMap;
#[allow(unused_imports)]
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
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

pub async fn setup_connection() -> anyhow::Result<(
    tokio::sync::mpsc::UnboundedSender<Request>,
    Arc<DashMap<String, String>>,
)> {
    info!("Connecting to server...");
    let stream = TcpStream::connect("192.168.8.121:8333").await?;
    let (reader, mut writer) = stream.into_split();
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    // 用 mpsc 让多个任务发消息到 writer 线程
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Request>();
    let wait_map = Arc::new(DashMap::new());

    // writer task
    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            let req_json = serde_json::to_string(&req).unwrap();
            if let Err(e) = writer.write_all(req_json.as_bytes()).await {
                error!("Failed to write to server: {}", e);
            }
            if let Err(e) = writer.write_all(b"\n").await {
                error!("Failed to write newline: {}", e);
            }
        }
    });

    // reader task
    let wait_map_reader = Arc::clone(&wait_map);
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            let resp: Response = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    error!("Failed to parse server response: {}", e);
                    continue;
                }
            };
            if let Some(path) = wait_map_reader.get(&resp.id) {
                info!("Server response for {}: {}", *path, resp.result);
            } else {
                warn!("Received response for unknown id: {}", resp.id);
            }
        }
    });
    info!("Connected to server");
    Ok((tx, wait_map))
}

pub async fn send_file(
    path: String,
    tx: tokio::sync::mpsc::UnboundedSender<Request>,
    wait_map: Arc<DashMap<String, String>>,
) -> anyhow::Result<()> {
    let id = Uuid::new_v4().to_string();

    let mut file = File::open(&path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;

    {
        wait_map.insert(id.clone(), path.clone());
    }

    let req = Request {
        id,
        path,
        content: contents,
    };

    tx.send(req)?;

    Ok(())
}
