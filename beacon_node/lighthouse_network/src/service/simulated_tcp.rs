//! TCP transport for virtual hosts. Protocol upgrades remain the production Noise/Yamux stack.

use futures::future::{BoxFuture, Ready, ready};
use futures::io::{AsyncRead, AsyncWrite};
use libp2p::core::transport::{DialOpts, ListenerId, TransportError, TransportEvent};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, Transport};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

type Event = TransportEvent<Ready<io::Result<Stream>>, io::Error>;
type Accept = BoxFuture<'static, (TcpListener, io::Result<(TcpStream, SocketAddr)>)>;

enum ListenerState {
    Binding(BoxFuture<'static, io::Result<TcpListener>>),
    Accepting(Accept),
}

struct Listener {
    id: ListenerId,
    address: Option<Multiaddr>,
    state: ListenerState,
}

#[derive(Default)]
pub(super) struct SimulatedTcp {
    listeners: VecDeque<Listener>,
    pending: VecDeque<Event>,
    waker: Option<Waker>,
}

pub(super) fn validate_config(config: &crate::NetworkConfig) -> Result<(), String> {
    for address in config.listen_addrs().libp2p_addresses() {
        // ListenAddress always includes QUIC addresses, even when QUIC is disabled.
        if address.iter().any(|protocol| protocol == Protocol::QuicV1) {
            continue;
        }
        if socket_addr(&address).is_none() {
            return Err(format!(
                "whole-node simulation requires explicit IPv4/TCP listen addresses, got {address}"
            ));
        }
    }
    if !config.disable_discovery
        && !matches!(
            &config.discv5_config.listen_config,
            discv5::ListenConfig::Ipv4 { ip, port }
                if !ip.is_unspecified() && *port != 0
        )
    {
        return Err(
            "whole-node simulation requires an explicit IPv4/UDP discovery listen address".into(),
        );
    }
    for enr in &config.boot_nodes_enr {
        if enr.ip6().is_some()
            || enr.udp6().is_some()
            || enr.tcp6().is_some()
            || enr
                .udp4_socket()
                .is_none_or(|socket| socket.ip().is_unspecified() || socket.port() == 0)
            || enr.tcp4().is_some_and(|port| port == 0)
        {
            return Err(
                "whole-node simulation requires boot ENRs with explicit IPv4 UDP sockets and no IPv6 sockets".into(),
            );
        }
    }
    for address in config
        .libp2p_nodes
        .iter()
        .chain(&config.boot_nodes_multiaddr)
    {
        if socket_addr(address).is_none_or(|socket| socket.port() == 0) {
            return Err(format!(
                "whole-node simulation requires explicit IPv4/TCP peer addresses, got {address}"
            ));
        }
    }
    Ok(())
}

fn socket_addr(address: &Multiaddr) -> Option<SocketAddr> {
    let mut protocols = address.iter();
    let ip = match protocols.next()? {
        Protocol::Ip4(ip) if !ip.is_unspecified() && !ip.is_multicast() => IpAddr::V4(ip),
        _ => return None,
    };
    let Protocol::Tcp(port) = protocols.next()? else {
        return None;
    };
    match (protocols.next(), protocols.next()) {
        (None, None) | (Some(Protocol::P2p(_)), None) => Some(SocketAddr::new(ip, port)),
        _ => None,
    }
}

fn multiaddr(address: SocketAddr) -> Multiaddr {
    Multiaddr::empty()
        .with(address.ip().into())
        .with(Protocol::Tcp(address.port()))
}

fn accepting(listener: TcpListener) -> ListenerState {
    ListenerState::Accepting(Box::pin(async move {
        let result = listener.accept().await;
        (listener, result)
    }))
}

impl SimulatedTcp {
    fn wake(&self) {
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
    }
}

impl Transport for SimulatedTcp {
    type Output = Stream;
    type Error = io::Error;
    type ListenerUpgrade = Ready<io::Result<Stream>>;
    type Dial = BoxFuture<'static, io::Result<Stream>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        let socket = socket_addr(&address)
            .ok_or_else(|| TransportError::MultiaddrNotSupported(address.clone()))?;
        self.listeners.push_back(Listener {
            id,
            address: None,
            state: ListenerState::Binding(Box::pin(TcpListener::bind(socket))),
        });
        self.wake();
        Ok(())
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        let Some(index) = self.listeners.iter().position(|listener| listener.id == id) else {
            return false;
        };
        if let Some(listener) = self.listeners.remove(index) {
            if let Some(listen_addr) = listener.address {
                self.pending.push_back(TransportEvent::AddressExpired {
                    listener_id: id,
                    listen_addr,
                });
            }
            self.pending.push_back(TransportEvent::ListenerClosed {
                listener_id: id,
                reason: Ok(()),
            });
        }
        self.wake();
        true
    }

    fn dial(
        &mut self,
        address: Multiaddr,
        _options: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let socket = socket_addr(&address)
            .filter(|socket| socket.port() != 0)
            .ok_or_else(|| TransportError::MultiaddrNotSupported(address.clone()))?;
        // Port reuse is best effort in the Transport contract. MadSim allocates a fresh source port.
        Ok(Box::pin(async move {
            let stream = TcpStream::connect(socket).await?;
            stream.set_nodelay(true)?;
            Ok(Stream(Some(stream)))
        }))
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Event> {
        self.waker = Some(cx.waker().clone());
        if let Some(event) = self.pending.pop_front() {
            return Poll::Ready(event);
        }
        // Rotate listeners so a busy host cannot starve another listening address.
        for _ in 0..self.listeners.len() {
            let Some(mut listener) = self.listeners.pop_front() else {
                break;
            };
            let listener_id = listener.id;
            let event = match &mut listener.state {
                ListenerState::Binding(future) => match future.as_mut().poll(cx) {
                    Poll::Pending => None,
                    Poll::Ready(result) => match result.and_then(|socket| {
                        let address = socket.local_addr()?;
                        Ok((socket, address))
                    }) {
                        Ok((socket, address)) => {
                            let listen_addr = multiaddr(address);
                            listener.address = Some(listen_addr.clone());
                            listener.state = accepting(socket);
                            Some(TransportEvent::NewAddress {
                                listener_id,
                                listen_addr,
                            })
                        }
                        Err(error) => {
                            return Poll::Ready(TransportEvent::ListenerClosed {
                                listener_id,
                                reason: Err(error),
                            });
                        }
                    },
                },
                ListenerState::Accepting(future) => match future.as_mut().poll(cx) {
                    Poll::Pending => None,
                    Poll::Ready((socket, result)) => {
                        listener.state = accepting(socket);
                        Some(
                            match result.and_then(|(stream, remote)| {
                                stream.set_nodelay(true)?;
                                let local = stream.local_addr()?;
                                Ok((stream, local, remote))
                            }) {
                                Ok((stream, local, remote)) => TransportEvent::Incoming {
                                    listener_id,
                                    upgrade: ready(Ok(Stream(Some(stream)))),
                                    local_addr: multiaddr(local),
                                    send_back_addr: multiaddr(remote),
                                },
                                Err(error) => TransportEvent::ListenerError { listener_id, error },
                            },
                        )
                    }
                },
            };
            self.listeners.push_back(listener);
            if let Some(event) = event {
                return Poll::Ready(event);
            }
        }
        Poll::Pending
    }
}

/// Bridges Tokio IO to futures IO and closes the virtual socket on `poll_close`.
/// MadSim's shutdown method alone does not currently close its sending channel.
pub(super) struct Stream(Option<TcpStream>);

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(stream) = self.0.as_mut() else {
            return Poll::Ready(Ok(0));
        };
        let mut buffer = ReadBuf::new(buffer);
        match Pin::new(stream).poll_read(cx, &mut buffer) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.0.as_mut() {
            Some(stream) => Pin::new(stream).poll_write(cx, buffer),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.0.as_mut() {
            Some(stream) => Pin::new(stream).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.0.take();
                Poll::Ready(result)
            }
        }
    }
}
