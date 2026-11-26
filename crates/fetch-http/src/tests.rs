use pellet_fetch::testing::{BODY, LARGE_LEN, SLOW_DELAY, Urls};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::*;

async fn answer(mut stream: TcpStream) {
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&buf[..n]),
        }
    }
    let line = String::from_utf8_lossy(&request);
    let path = line.split_whitespace().nth(1).unwrap_or("/").to_owned();
    let (status, body) = match path.as_str() {
        "/ok" => ("200 OK", BODY.to_vec()),
        "/large" => ("200 OK", vec![b'x'; LARGE_LEN]),
        "/slow" => {
            tokio::time::sleep(SLOW_DELAY).await;
            ("200 OK", BODY.to_vec())
        }
        _ => ("404 Not Found", b"missing".to_vec()),
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(&body).await;
    let _ = stream.shutdown().await;
}

async fn serve() -> Urls {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(answer(stream));
        }
    });
    Urls {
        ok: format!("{base}/ok"),
        large: format!("{base}/large"),
        missing: format!("{base}/missing"),
        slow: format!("{base}/slow"),
    }
}

#[tokio::test]
async fn conformance() {
    let urls = serve().await;
    pellet_fetch::testing::conformance(&HttpFetch::new().unwrap(), &urls).await;
}
