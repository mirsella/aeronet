#![expect(missing_docs, reason = "testing")]
#![cfg(not(target_family = "wasm"))]

use {
    aeronet_io::{Session, connection::Disconnected},
    aeronet_websocket::{
        client::{ClientConfig, WebSocketClient, WebSocketClientPlugin},
        tungstenite::{
            Message,
            protocol::{CloseFrame, frame::coding::CloseCode},
        },
    },
    bevy::prelude::*,
    core::time::Duration,
    futures::{SinkExt, StreamExt},
    std::sync::mpsc,
};

const LAST_WORDS: &[u8] = b"match cancelled";

#[derive(Resource, Default)]
struct Seen(Vec<&'static str>);

/// A peer that sends a frame and closes before the client's next update must
/// still have that frame delivered before the session disconnects.
#[test]
fn frames_sent_before_a_close_are_received_before_the_disconnect() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx_go, rx_go) = futures::channel::oneshot::channel::<()>();
    let (tx_closed, rx_closed) = mpsc::channel::<()>();
    runtime.spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        rx_go.await.unwrap();
        socket
            .send(Message::Binary(LAST_WORDS.into()))
            .await
            .unwrap();
        socket
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Away,
                reason: "restarting".into(),
            })))
            .await
            .unwrap();
        // The client answers the close only after reading every frame before
        // it.
        while socket.next().await.is_some() {}
        tx_closed.send(()).unwrap();
    });

    let mut app = App::new();
    app.add_plugins((MinimalPlugins, WebSocketClientPlugin))
        .init_resource::<Seen>()
        .add_systems(
            Update,
            |mut sessions: Query<&mut Session>, mut seen: ResMut<Seen>| {
                for mut session in &mut sessions {
                    for packet in session.recv.drain(..) {
                        assert_eq!(&packet.payload[..], LAST_WORDS);
                        seen.0.push("frame");
                    }
                }
            },
        )
        .add_observer(|_: On<Disconnected>, mut seen: ResMut<Seen>| {
            seen.0.push("disconnected");
        });
    let entity = app.world_mut().spawn_empty();
    WebSocketClient::connect(
        ClientConfig::builder().with_no_encryption(),
        format!("ws://127.0.0.1:{port}"),
    )
    .apply(entity);

    while app.world_mut().query::<&Session>().iter(app.world()).len() == 0 {
        app.update();
    }
    tx_go.send(()).unwrap();
    rx_closed.recv_timeout(Duration::from_secs(10)).unwrap();
    // Give the client task time to report the close it already answered.
    std::thread::sleep(Duration::from_millis(100));

    for _ in 0..3 {
        app.update();
    }
    assert_eq!(app.world().resource::<Seen>().0, ["frame", "disconnected"]);
}
