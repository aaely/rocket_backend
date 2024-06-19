use crate::structs::*;
use rocket::{get, State};
use tokio_native_tls::TlsAcceptor;
use native_tls::{Identity, TlsAcceptor as NativeTlsAcceptor};
use rocket::tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};
use std::{fs::File, net::SocketAddr};
use std::io::Read;
use futures_util::{SinkExt, StreamExt};

#[get("/ws")]
pub async fn ws_handler(state: &State<AppState>) -> Result<(), rocket::http::Status> {
    let ws_list = state.ws_list.clone();
    tokio::spawn(async move {
        if let Err(e) = run_ws_server(ws_list).await {
            println!("Error in WebSocket server: {}", e);
        }
    });

    Ok(())
}

async fn run_ws_server(ws_list: WebSocketList) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("0.0.0.0:9001").await?;

    // Load the SSL keys and certificates
    let mut key_file = File::open("certs/server.key")
        .expect("Failed to open key file");
    let mut key = vec![];
    key_file.read_to_end(&mut key)
        .expect("Failed to read key file");

    let mut cert_file = File::open("/usr/local/share/ca-certificates/server.crt")
        .expect("Failed to open cert file");
    let mut cert = vec![];
    cert_file.read_to_end(&mut cert)
        .expect("Failed to read cert file");

    let identity = Identity::from_pkcs8(&cert, &key)?;
    let acceptor = TlsAcceptor::from(NativeTlsAcceptor::builder(identity).build()?);

    while let Ok((stream, _)) = listener.accept().await {
        let peer_addr = stream.peer_addr().expect("connected streams should have a peer address");
        let acceptor = acceptor.clone();
        let ws_list_inner = ws_list.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = handle_connection(tls_stream, peer_addr, ws_list_inner).await {
                        println!("Error in WebSocket connection: {}", e);
                    }
                },
                Err(e) => println!("TLS accept error: {}", e),
            }
        });
    }

    Ok(())
}

async fn handle_connection<S>(
    stream: S,
    peer_addr: SocketAddr,
    ws_list: WebSocketList,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ws_stream = accept_async(stream).await.expect("Error during the websocket handshake occurred");
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    {
        let mut ws_list = ws_list.lock().await;
        ws_list.insert(peer_addr, tx);
    }

    // Clone ws_list for the incoming messages task
    let ws_list_for_incoming = ws_list.clone();
    // Task to handle incoming messages from the WebSocket connection
    tokio::spawn(async move {
        while let Some(message) = ws_receiver.next().await {
            match message {
                Ok(msg) => {
                    if msg.is_text() {
                        let msg_text = msg.to_text().unwrap();
                        match serde_json::from_str::<IncomingMessage>(msg_text) {
                            Ok(incoming_message) => {
                                match incoming_message.r#type.as_str() {
                                    "hot_trailer" => {
                                        println!("Handling hot_trailer: {:?}", incoming_message.data);
                                    }
                                    "schedule_trailer" => {
                                        println!("Handling schedule_trailer: {:?}", incoming_message.data);
                                    }
                                    "set_door" => {
                                        println!("Handling set_door: {:?}", incoming_message.data);
                                    }
                                    "trailer_arrived" => {
                                        println!("Handling trailer_arrived: {:?}", incoming_message.data);
                                    }
                                    _ => {
                                        println!("Unknown event type: {:?}", incoming_message.r#type);
                                    }
                                }

                                // Broadcast the message to all connected clients
                                let response = Message::Text(serde_json::to_string(&incoming_message).unwrap());
                                let ws_list = ws_list_for_incoming.lock().await;
                                for sender in ws_list.values() {
                                    if sender.send(response.clone()).is_err() {
                                        println!("Failed to send message");
                                    }
                                }
                            }
                            Err(e) => {
                                println!("Failed to parse incoming message: {:?}", e);
                            }
                        }
                    } else if msg.is_binary() {
                        println!("Received binary message");
                    } else if msg.is_close() {
                        println!("Received close message");
                        break;
                    }
                }
                Err(e) => {
                    println!("WebSocket error: {}", e);
                    break;
                }
            }
        }
    });

    // Clone ws_list for the outgoing messages task
    let ws_list_for_outgoing = ws_list.clone();
    // Task to handle outgoing messages to the WebSocket connection
    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if ws_sender.send(message).await.is_err() {
                println!("Failed to send message");
                break;
            }
        }

        // Clean up the WebSocket list after the connection is closed
        let mut ws_list = ws_list_for_outgoing.lock().await;
        ws_list.remove(&peer_addr);
    });

    Ok(())
}