use std::{io::ErrorKind, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

const ADDRESS: &str = "10.0.0.1:9000";
const DEADLINE: Duration = Duration::from_secs(2);

async fn exchange_server(stream: &mut TcpStream, expected: &[u8]) {
    let mut received = vec![0; expected.len()];
    timeout(DEADLINE, stream.read_exact(&mut received))
        .await
        .expect("established stream stopped receiving")
        .unwrap();
    assert_eq!(received, expected);
    stream.write_all(&received).await.unwrap();
    stream.flush().await.unwrap();
}

async fn exchange_client(stream: &mut TcpStream, message: &[u8]) {
    stream.write_all(message).await.unwrap();
    stream.flush().await.unwrap();
    let mut received = vec![0; message.len()];
    timeout(DEADLINE, stream.read_exact(&mut received))
        .await
        .expect("established stream stopped echoing")
        .unwrap();
    assert_eq!(received, message);
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "listener".into());
    assert!(matches!(mode.as_str(), "listener" | "half-close"));
    let mut runtime = madsim::runtime::Runtime::with_seed_and_config(42, Default::default());
    runtime.set_time_limit(Duration::from_secs(30));
    let server = runtime
        .create_node()
        .ip("10.0.0.1".parse().unwrap())
        .build();
    let client = runtime
        .create_node()
        .ip("10.0.0.2".parse().unwrap())
        .build();
    let (ready, waiting) = oneshot::channel();

    if mode == "listener" {
        let (dropped, after_drop) = oneshot::channel();
        let (rebound, after_rebind) = oneshot::channel();
        let (old_dropped, after_old_drop) = oneshot::channel();
        let serving = server.spawn(async move {
            let listener = TcpListener::bind(ADDRESS).await.unwrap();
            ready.send(()).unwrap();
            let (mut old, _) = listener.accept().await.unwrap();
            drop(listener);
            dropped.send(()).unwrap();

            exchange_server(&mut old, b"before rebind").await;
            println!("existing_connection_survives_listener_drop=true");
            let replacement = TcpListener::bind(ADDRESS).await;
            println!("rebind_with_old_stream_alive={}", replacement.is_ok());
            rebound.send(replacement.is_ok()).unwrap();
            let replacement = replacement.expect("dropped listener still owns its address");
            let (mut new, _) = replacement.accept().await.unwrap();
            exchange_server(&mut old, b"old connection after rebind").await;
            drop(old);
            old_dropped.send(()).unwrap();
            exchange_server(&mut new, b"replacement connection").await;
            // Old accepted connection destruction must not unregister the replacement.
            let (mut newest, _) = replacement.accept().await.unwrap();
            exchange_server(&mut newest, b"replacement still listening").await;
        });
        let requesting = client.spawn(async move {
            waiting.await.unwrap();
            let mut old = TcpStream::connect(ADDRESS).await.unwrap();
            after_drop.await.unwrap();
            let refused = match TcpStream::connect(ADDRESS).await {
                Err(error) => {
                    assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
                    true
                }
                Ok(stream) => {
                    drop(stream);
                    false
                }
            };
            println!("dropped_listener_refuses_new_connections={refused}");
            exchange_client(&mut old, b"before rebind").await;
            if after_rebind.await.unwrap() {
                let mut new = TcpStream::connect(ADDRESS).await.unwrap();
                exchange_client(&mut old, b"old connection after rebind").await;
                after_old_drop.await.unwrap();
                exchange_client(&mut new, b"replacement connection").await;
                let mut newest = TcpStream::connect(ADDRESS).await.unwrap();
                exchange_client(&mut newest, b"replacement still listening").await;
            }
            assert!(refused, "connect succeeded after its listener was dropped");
        });
        runtime.block_on(async {
            serving.await.unwrap();
            requesting.await.unwrap();
        });
        println!("listener_lifecycle=verified");
    } else {
        const REQUEST: &[u8] = b"GET / HTTP/1.0\r\nHost: example\r\n\r\n";
        const RESPONSE: &[u8] = b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nok";
        let serving = server.spawn(async move {
            let listener = TcpListener::bind(ADDRESS).await.unwrap();
            ready.send(()).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            timeout(DEADLINE, stream.read_to_end(&mut request))
                .await
                .expect("shutdown did not flush buffered request and deliver EOF")
                .unwrap();
            assert_eq!(request, REQUEST);
            // No explicit flush: AsyncWrite shutdown must flush and then send EOF.
            stream.write_all(RESPONSE).await.unwrap();
            stream.shutdown().await.unwrap();
            stream.shutdown().await.unwrap();
            assert_eq!(
                stream.write_all(b"late").await.unwrap_err().kind(),
                ErrorKind::BrokenPipe
            );
        });
        let requesting = client.spawn(async move {
            waiting.await.unwrap();
            let mut stream = TcpStream::connect(ADDRESS).await.unwrap();
            stream.write_all(REQUEST).await.unwrap();
            stream.shutdown().await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            timeout(DEADLINE, stream.read_to_end(&mut response))
                .await
                .expect("write-half shutdown blocked the response or failed to deliver EOF")
                .unwrap();
            assert_eq!(response, RESPONSE);
            assert_eq!(
                stream.write_all(b"late").await.unwrap_err().kind(),
                ErrorKind::BrokenPipe
            );
        });
        runtime.block_on(async {
            serving.await.unwrap();
            requesting.await.unwrap();
        });
        println!("half_close_flush_eof_response_and_write_rejection=verified");
    }
}
