use super::{DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT, Server, ServerError};
use futures::{StreamExt, stream::FuturesUnordered};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
    service::TowerToHyperService,
};
use std::net::SocketAddr;

// Only the socket/executor boundary differs: the production Router (including
// the warp fallback and every middleware layer) receives the real HTTP bytes.
pub(super) async fn serve<F>(
    server: Server,
    shutdown_signal: F,
) -> Result<(SocketAddr, impl Future<Output = Result<(), ServerError>>), ServerError>
where
    F: Future<Output = ()> + Send + 'static,
{
    if server.rustls_config.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TLS HTTP servers are not supported in simulation",
        )
        .into());
    }
    let listener = tokio::net::TcpListener::bind(server.address).await?;
    let address = listener.local_addr()?;
    let future = async move {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut connections = FuturesUnordered::new();
        tokio::pin!(shutdown_signal);
        loop {
            tokio::select! {
                _ = &mut shutdown_signal => break,
                _ = connections.next(), if !connections.is_empty() => {},
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let service = TowerToHyperService::new(server.router.clone());
                    let mut shutdown = shutdown_rx.clone();
                    connections.push(async move {
                        let mut builder = auto::Builder::new(TokioExecutor::new());
                        builder.http1().timer(TokioTimer::new());
                        builder.http2().timer(TokioTimer::new());
                        let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
                        tokio::pin!(connection);
                        let result = tokio::select! {
                            result = &mut connection => result,
                            _ = shutdown.changed() => {
                                connection.as_mut().graceful_shutdown();
                                connection.await
                            }
                        };
                        if let Err(error) = result {
                            tracing::debug!(%error, "HTTP connection closed with an error");
                        }
                    });
                }
            }
        }
        // Stop accepting immediately, then allow in-flight handlers the same
        // grace period as the native server. Dropping the remaining futures
        // closes their virtual streams rather than leaking detached tasks.
        drop(listener);
        let _ = shutdown_tx.send(true);
        let drain = async { while connections.next().await.is_some() {} };
        let _ = tokio::time::timeout(DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT, drain).await;
        Ok(())
    };
    Ok((address, future))
}
