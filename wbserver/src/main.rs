use std::{collections::HashSet, path::PathBuf, sync::Arc};

use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{RwLock, broadcast},
};

#[derive(Deserialize, Serialize, Debug)]
struct Request {
    id: String,
    path: String,
    content: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct Response {
    id: String,
    result: String,
}

#[derive(Debug, Clone)]
struct Task {
    id: String,
    path: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let listener = TcpListener::bind("0.0.0.0:8333").await?;
    info!("Server listening on 0.0.0.0:8333");

    let (task_tx, _) = broadcast::channel::<Task>(1000);
    let completed = Arc::new(RwLock::new(HashSet::new()));

    spawn_worker("gradio", task_tx.subscribe(), Arc::clone(&completed));
    spawn_worker("signature", task_tx.subscribe(), Arc::clone(&completed));

    loop {
        let (socket, addr) = listener.accept().await?;
        info!("New connection from {:?}", addr);

        let tx_clone = task_tx.clone();
        let completed = Arc::clone(&completed);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, tx_clone, completed, addr).await {
                error!("Connection handler error: {:#}", e);
            }
        });
    }
}

async fn handle_connection(
    socket: TcpStream,
    task_tx: broadcast::Sender<Task>,
    completed: Arc<RwLock<HashSet<String>>>,
    addr: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let (reader, mut writer) = socket.into_split();
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let req: Request = serde_json::from_str(&line)?;
        debug!("Received task: {:?}", req);

        // 保存 content 到临时文件
        let sub_dir = format!("{}", addr);
        let tmp_path = save_content_to_file(&req.id, &req.content, sub_dir).await?;

        let task = Task {
            id: req.id.clone(),
            path: tmp_path.clone(),
        };

        // 发送任务，如果队列满，降级处理
        if let Err(e) = task_tx.send(task) {
            error!("任务队列发送失败，任务 {} 被丢弃: {}", req.id, e);
            let resp = Response {
                id: req.id,
                result: "任务队列发送失败，任务被拒绝".to_string(),
            };
            let resp_json = serde_json::to_string(&resp)?;
            writer.write_all(resp_json.as_bytes()).await?;
            writer.write_all(b"\n").await?;
        }
    }

    Ok(())
}

fn spawn_worker(
    name: &str,
    mut rx: broadcast::Receiver<Task>,
    completed: Arc<RwLock<HashSet<String>>>,
) {
    let name = name.to_string();
    tokio::spawn(async move {
        loop {
            let task = match rx.recv().await {
                Ok(task) => task,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    error!("[{}] 丢失了 {} 个任务", name, n);
                    continue;
                }
                Err(e) => {
                    error!("[{}] 接收任务失败: {}", name, e);
                    break;
                }
            };

            // 如果已完成则跳过
            if completed.read().await.contains(&task.id) {
                debug!("[{}] 跳过重复任务: {}", name, task.id);
                continue;
            }

            // 模拟执行检测逻辑（调用 Python 或模型）
            let result = run_detector(&name, &task).await;

            // 再次检查是否已完成（竞态保护）
            let mut guard = completed.write().await;
            if guard.contains(&task.id) {
                debug!("[{}] 任务 {} 已由他人完成，结果丢弃", name, task.id);
                continue;
            }

            guard.insert(task.id.clone());
            drop(guard);

            info!("[{}] 任务 {} 检测完成: {}", name, task.id, result);

            // TODO: 将结果返回给前端（或发送 socket/HTTP）
        }
    });
}

async fn run_detector(name: &str, task: &Task) -> String {
    let client = reqwest::Client::new();
    let code =
        std::fs::read_to_string(&task.path).unwrap_or_else(|_| "Failed to read file".to_string());

    // 构造请求体 JSON
    let request_body = serde_json::json!({
        "code": code,
    });

    // 发送 POST 请求
    let response = match client
        .post("http://127.0.0.1:7860/predict")
        .json(&request_body)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to send request: {}", e);
            return format!("[{}] 检测失败: {}", name, task.path.display());
        }
    };

    // 解析响应
    if let Ok(result_text) = response.text().await {
        println!("Response: {}", result_text);
        format!("[{}] 检测结果: {}", name, task.path.display())
    } else {
        println!("Failed to get response");
        format!("[{}] 检测失败: {}", name, task.path.display())
    }
}

async fn save_content_to_file(id: &str, content: &str, sub_dir: String) -> anyhow::Result<PathBuf> {
    let dir = std::env::current_dir()?.join(sub_dir);
    fs::create_dir_all(&dir).await?;
    let path = dir.join(format!("{}", id));
    fs::write(&path, content).await?;
    Ok(path)
}
