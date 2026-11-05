use {
    super::{ServerConfig, ServerError, ToConnected, ToOpen},
    crate::{
        server::{HandshakeHandler, ToConnecting},
        session::SessionError,
    },
    aeronet_io::{connection::DisconnectReason, server::CloseReason},
    bevy_ecs::prelude::*,
    core::{
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    },
    futures::{
        FutureExt, SinkExt, StreamExt,
        channel::{mpsc, oneshot},
        never::Never,
    },
    tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        net::{TcpListener, TcpStream},
        time::{Instant, timeout_at},
    },
    tokio_rustls::TlsAcceptor,
    tokio_tungstenite::tungstenite::{
        handshake::server::{Request, Response},
        protocol::WebSocketConfig,
    },
    tracing::{Instrument, debug, debug_span},
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn start(
    config: ServerConfig,
    tx_next: oneshot::Sender<ToOpen>,
) -> Result<Never, CloseReason> {
    let tls_acceptor = config.tls.map(TlsAcceptor::from);
    let listener = TcpListener::bind(config.bind_address)
        .await
        .map_err(ServerError::BindSocket)?;
    debug!("Listening on {}", config.bind_address);

    let (tx_connecting, rx_connecting) = mpsc::channel::<ToConnecting>(1);
    let (tx_dropped, mut rx_dropped) = mpsc::channel::<()>(0);

    let local_addr = listener.local_addr().map_err(SessionError::GetLocalAddr)?;
    let next = ToOpen {
        local_addr,
        rx_connecting,
        tx_dropped,
    };
    tx_next
        .send(next)
        .map_err(|_| SessionError::FrontendClosed)?;

    debug!("Starting server loop");
    loop {
        let result = futures::select! {
            x = listener.accept().fuse() => x,
            _ = rx_dropped.next() => {
                return Err(CloseReason::ByError(SessionError::FrontendClosed.into()));
            }
        };
        let (stream, peer_addr) = result.map_err(ServerError::AcceptConnection)?;

        tokio::spawn({
            let tx_connecting = tx_connecting.clone();
            let tls_acceptor = tls_acceptor.clone();
            let handshake_handler = config.handshake_handler.clone();
            async move {
                if let Err(err) = accept_session(
                    stream,
                    peer_addr,
                    config.socket,
                    tls_acceptor,
                    tx_connecting,
                    handshake_handler,
                )
                .await
                {
                    debug!("Failed to accept session: {err:?}");
                }
            }
        });
    }
}

async fn accept_session(
    stream: TcpStream,
    peer_addr: SocketAddr,
    socket_config: WebSocketConfig,
    tls_acceptor: Option<TlsAcceptor>,
    mut tx_connecting: mpsc::Sender<ToConnecting>,
    handshake_handler: Option<HandshakeHandler>,
) -> Result<(), DisconnectReason> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let (tx_session_entity, rx_session_entity) = oneshot::channel::<Entity>();
    let (tx_dc_reason, rx_dc_reason) = oneshot::channel::<DisconnectReason>();
    let (tx_next, rx_next) = oneshot::channel::<ToConnected>();
    timeout_at(
        deadline,
        tx_connecting.send(ToConnecting {
            peer_addr,
            tx_session_entity,
            rx_dc_reason,
            rx_next,
        }),
    )
    .await
    .map_err(|_| ServerError::HandshakeTimeout)?
    .map_err(|_| SessionError::FrontendClosed)?;
    let session = timeout_at(deadline, rx_session_entity)
        .await
        .map_err(|_| ServerError::HandshakeTimeout)?
        .map_err(|_| SessionError::FrontendClosed)?;

    let Err(dc_reason) = handle_session(
        stream,
        peer_addr,
        socket_config,
        tls_acceptor,
        tx_next,
        handshake_handler,
        deadline,
    )
    .instrument(debug_span!("session", %session))
    .await;
    _ = tx_dc_reason.send(dc_reason);
    Ok(())
}

async fn handle_session(
    stream: TcpStream,
    peer_addr: SocketAddr,
    socket_config: WebSocketConfig,
    tls_acceptor: Option<TlsAcceptor>,
    mut tx_next: oneshot::Sender<ToConnected>,
    handshake_handler: Option<HandshakeHandler>,
    deadline: Instant,
) -> Result<Never, DisconnectReason> {
    debug!("Performing session handshake");

    let handshake = async {
        let stream = if let Some(tls_acceptor) = tls_acceptor {
            tls_acceptor
                .accept(stream)
                .await
                .map(MaybeTlsStream::Rustls)
                .map_err(ServerError::TlsHandshake)?
        } else {
            MaybeTlsStream::Plain(stream)
        };
        let stream = tokio_tungstenite::accept_hdr_async_with_config(
            stream,
            #[expect(
                clippy::result_large_err,
                reason = "this `Result` is what `tokio_tungstenite` asks for"
            )]
            |req: &Request, resp: Response| match &handshake_handler {
                Some(h) => h.handle(req, resp),
                None => Ok(resp),
            },
            Some(socket_config),
        )
        .await
        .map_err(ServerError::AcceptClient)?;
        Ok::<_, ServerError>(stream)
    };
    futures::pin_mut!(handshake);
    // Dropping this future also drops the TCP stream, including partial
    // TLS/HTTP upgrades. A frontend evicted before connection must not
    // leave a backend task.
    let stream = futures::select! {
        () = tx_next.cancellation().fuse() => return Err(SessionError::FrontendClosed.into()),
        result = timeout_at(deadline, handshake).fuse() => {
            result.map_err(|_| ServerError::HandshakeTimeout)??
        }
    };

    let (frontend, backend) = crate::session::backend::native::split(stream);
    let connected = ToConnected {
        peer_addr,
        frontend,
    };
    debug!("Connected");

    tx_next
        .send(connected)
        .map_err(|_| SessionError::FrontendClosed)?;

    debug!("Starting session loop");
    backend.start().await
}

#[derive(Debug)]
#[expect(clippy::large_enum_variant, reason = "most users will use `Rustls`")]
enum MaybeTlsStream<S> {
    Plain(S),
    Rustls(tokio_rustls::server::TlsStream<S>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaybeTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Rustls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MaybeTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Rustls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Rustls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Rustls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        tokio::io::{AsyncReadExt, AsyncWriteExt},
    };

    #[test]
    fn pending_upgrade_closes_with_frontend_or_deadline() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for frontend_closes in [true, false] {
                let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                    .await
                    .unwrap();
                let mut peer = TcpStream::connect(listener.local_addr().unwrap())
                    .await
                    .unwrap();
                let (stream, address) = listener.accept().await.unwrap();
                let (tx, rx) = oneshot::channel();
                // A syntactically incomplete request never reaches the header
                // callback.
                peer.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
                    .await
                    .unwrap();
                let deadline = Instant::now()
                    + if frontend_closes {
                        Duration::from_secs(5)
                    } else {
                        Duration::from_millis(50)
                    };
                let task = tokio::spawn(handle_session(
                    stream,
                    address,
                    WebSocketConfig::default(),
                    None,
                    tx,
                    None,
                    deadline,
                ));
                let mut frontend = Some(rx);
                if frontend_closes {
                    drop(frontend.take());
                }
                let error = tokio::time::timeout(Duration::from_secs(1), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap_err();
                drop(frontend);
                let DisconnectReason::ByError(error) = error else {
                    panic!("unexpected disconnect reason");
                };
                if frontend_closes {
                    assert!(matches!(
                        error.downcast_ref::<SessionError>(),
                        Some(SessionError::FrontendClosed)
                    ));
                } else {
                    assert!(matches!(
                        error.downcast_ref::<ServerError>(),
                        Some(ServerError::HandshakeTimeout)
                    ));
                }
                let mut byte = [0];
                let closed = tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte))
                    .await
                    .unwrap();
                match closed {
                    Ok(0) => {}
                    // The canceled frontend can drop before HTTP bytes are read.
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                    other => panic!("pending socket was not closed: {other:?}"),
                }
            }
        });
    }

    #[cfg(feature = "aws-lc-rs")]
    #[test]
    fn pending_tls_closes_when_frontend_disappears() {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let mut peer = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, address) = listener.accept().await.unwrap();
            let config = ServerConfig::builder()
                .with_bind_address(address)
                .with_identity(super::super::Identity::self_signed(["localhost"]).unwrap());
            let (tx, rx) = oneshot::channel();
            let task = tokio::spawn(handle_session(
                stream,
                address,
                config.socket,
                config.tls.map(TlsAcceptor::from),
                tx,
                None,
                Instant::now() + HANDSHAKE_TIMEOUT,
            ));
            drop(rx);
            let error = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            let DisconnectReason::ByError(error) = error else {
                panic!("unexpected disconnect reason");
            };
            assert!(matches!(
                error.downcast_ref::<SessionError>(),
                Some(SessionError::FrontendClosed)
            ));
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        });
    }
}
