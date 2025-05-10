#![allow(unused)]
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::mpsc,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:8333").await?;
    println!("Server listening on 0.0.0.0:8333");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection from {:?}", addr);
        tokio::spawn(handle_connection(socket));
    }
}

async fn handle_connection(mut socket: TcpStream) -> anyhow::Result<()> {
    let (reader, mut writer) = socket.into_split();
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    // 模拟任务队列
    let (tx, mut rx) = mpsc::channel(100);

    // 接收并投递到任务队列
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            let req: Request = serde_json::from_str(&line).unwrap();
            println!("Received task: {:?}", req);
            tx_clone.send(req).await.unwrap();
        }
    });

    // 消费任务队列并发送回客户端
    while let Some(req) = rx.recv().await {
        let resp = Response {
            id: req.id,
            result: format!("Received file from {}", req.path),
        };
        let resp_json = serde_json::to_string(&resp)?;
        writer.write_all(resp_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
    Ok(())
}
