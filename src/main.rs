#[macro_use] extern crate rocket;

mod auth;
mod role;

use jsonwebtoken::{encode, Header, EncodingKey};
use rocket::{get, post, response::status::BadRequest, routes, serde::json::Json, State};
use neo4rs::{Graph, query, Node};
use tokio::sync::{mpsc::UnboundedSender, Mutex};
use std::{collections::HashMap, fs::File, net::{IpAddr, SocketAddr}, path::Path, sync::Arc};
use serde::{Deserialize, Serialize};
use auth::{decode_token, AuthenticatedUser, Claims};
use role::Role;
use bcrypt::{hash, verify, DEFAULT_COST};
use rocket::config::{Config};
use rocket::figment::Figment;
use tokio_native_tls::TlsAcceptor;
use native_tls::{Identity, TlsAcceptor as NativeTlsAcceptor};
use chrono::{Utc, Duration};
use std::io::Read;
use futures_util::{SinkExt, StreamExt};
use rocket::tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message, WebSocketStream};
use rocket_cors::{CorsOptions, AllowedOrigins, AllowedHeaders, Cors};
use rocket_multipart_form_data::{MultipartFormData, MultipartFormDataOptions, MultipartFormDataField, RawField, MultipartFormDataError};

type WebSocketList = Arc<Mutex<HashMap<SocketAddr, UnboundedSender<Message>>>>;

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct TodaysTrucksRequest {
    date: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    user: UserResponse,
    refresh_token: Option<String>,
}

#[derive(Serialize)]
struct UserResponse {
    username: String,
    role: String,
}

#[derive(Serialize, Deserialize)]
struct User {
    name: String,
    password: String,
    role: String
}

#[derive(Deserialize)]
struct LoadInfoRequest {
    param: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Part {
    partNumber: String,
    quantity: i32,
}

#[derive(Serialize, Deserialize)]
struct Trailer {
    TrailerID: String,
    Schedule: Schedule,
    CiscoIDs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Sids {
    TrailerID: String,
    Sids: Vec<SidAndParts>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SidAndParts {
    Sid: String,
    Cisco: String,
    Part: String,
    Quantity: i32,
}

#[derive(Deserialize)]
struct DateRangeTruckRequest {
    date1: String,
    date2: String,
}

#[derive(Serialize)]
struct TrailerResponse {
    TrailerID: String,
    Sids: Vec<SidAndParts>
}

#[derive(Serialize, Deserialize)]
struct SidParts {
    Sid: Sid,
    Parts: Vec<Part>,
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct IncomingMessage {
    r#type: String,
    data: MessageData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct MessageData {
    message: String,
}

#[derive(Deserialize, Debug)]
struct SetScheduleRequest {
    TrailerID: String,
    ScheduleDate: String,
    RequestDate: String,
    CarrierCode: String,
    ScheduleTime: String,
    LastFreeDate: String,
    ContactEmail: String,
    Door: String,
}

#[derive(Deserialize, Debug)]
struct SetArrivalTimeRequest {
    TrailerID: String,
    ArrivalTime: String,
}

#[derive(Serialize, Debug)]
struct TrailerSchedule {
    TrailerID: String,
    Schedule: Schedule,
}

#[derive(Deserialize, Debug)]
struct SetDoorRequest {
    TrailerID: String,
    Door: String,
}

#[derive(Deserialize, Debug)]
struct HotTrailerRequest {
    TrailerID: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Schedule {
    ScheduleDate: String,
    ScheduleTime: String,
    ArrivalTime: String,
    CarrierCode: String,
    ContactEmail: String,	
    DoorNumber: String,
    IsHot: bool,
    LastFreeDate: String,
    LoadStatus: String,
    RequestDate: String,
}

#[derive(Serialize, Deserialize)]
struct Sid {
    CiscoID: String,
    id: String,
}

struct AppState {
    graph: Arc<Graph>,
    jwt_secret: String,
    ws_list: WebSocketList,
}

#[derive(Deserialize)]
struct SidsRequest {
    date: String,
}

/*
    Auth routes
*/

#[post("/login", format = "json", data = "<login_request>")]
async fn login(login_request: Json<LoginRequest>, state: &State<AppState>) -> Result<Json<LoginResponse>, Json<String>> {
    let graph = &state.graph;

    let query = query("
        USE trucks MATCH (u:User {name: $username}) RETURN u
    ").param("username", login_request.username.clone());

    let mut result = match graph.execute(query).await {
        Ok(r) => r,
        Err(e) => return Err(Json(e.to_string())),
    };

    if let Some(record) = result.next().await.unwrap() {
        let user_node: Node = record.get("u").unwrap();

        let stored_password: String = user_node.get::<String>("password").unwrap().to_string();
        let username: String = user_node.get::<String>("name").unwrap().to_string();
        let role: String = user_node.get::<String>("role").unwrap().to_string();

        let is_password_valid = match verify(&login_request.password, &stored_password) {
            Ok(valid) => valid,
            Err(e) => return Err(Json(e.to_string())),
        };

        if is_password_valid {
            let access_expiration = Utc::now()
                .checked_add_signed(Duration::seconds(3600))
                .expect("valid timestamp")
                .timestamp() as usize;

            let refresh_expiration = Utc::now()
                .checked_add_signed(Duration::days(30))
                .expect("valid timestamp")
                .timestamp() as usize;

            let access_token = match encode(
                &Header::default(),
                &Claims { username: username.clone(), role: role.clone(), exp: access_expiration },
                &EncodingKey::from_secret(state.jwt_secret.as_ref()),
            ) {
                Ok(t) => t,
                Err(e) => return Err(Json(e.to_string())),
            };

            let refresh_token = match encode(
                &Header::default(),
                &Claims { username: username.clone(), role: role.clone(), exp: refresh_expiration },
                &EncodingKey::from_secret(state.jwt_secret.as_ref()),
            ) {
                Ok(t) => t,
                Err(e) => return Err(Json(e.to_string())),
            };

            let response = LoginResponse {
                token: access_token,
                refresh_token: Some(refresh_token),  // Add this field in the response
                user: UserResponse {
                    username,
                    role,
                },
            };
            return Ok(Json(response));
        } else {
            return Err(Json("Invalid password".to_string()));
        }
    } else {
        return Err(Json("User not found".to_string()));
    }
}

#[post("/register", format = "json", data = "<user>")]
async fn register(user: Json<LoginRequest>, state: &State<AppState>) -> Result<Json<&'static str>, String> {
    let graph = &state.graph;

    let hashed_password = match hash(&user.password, DEFAULT_COST) {
        Ok(p) => p,
        Err(e) => return Err(e.to_string()),
    };

    println!("{} {}", user.username.clone(), hashed_password);

    let query = query(" USE trucks CREATE (u:User {name: $username, password: $password, role: 'read'})")
        .param("username", user.username.clone())
        .param("password", hashed_password);

    match graph.run(query).await {
        Ok(_) => Ok(Json("User registered")),
        Err(e) => Err(format!("Failed to register user: {:?}", e)),
    }
}

#[post("/refresh", format = "json", data = "<refresh_request>")]
async fn refresh_token(refresh_request: Json<RefreshRequest>, state: &State<AppState>) -> Result<Json<LoginResponse>, Json<String>> {
    let claims = match decode_token(&refresh_request.refresh_token, &state.jwt_secret) {
        Ok(claims) => claims,
        Err(_) => return Err(Json("Invalid refresh token".to_string())),
    };

    let new_expiration = Utc::now()
        .checked_add_signed(Duration::seconds(3600))
        .expect("valid timestamp")
        .timestamp() as usize;

    let new_token = match encode(
        &Header::default(),
        &Claims {
            username: claims.username.clone(),
            role: claims.role.clone(),
            exp: new_expiration,
        },
        &EncodingKey::from_secret(state.jwt_secret.as_ref()),
    ) {
        Ok(t) => t,
        Err(e) => return Err(Json(e.to_string())),
    };

    let response = LoginResponse {
        token: new_token,
        refresh_token: None,  // Do not issue a new refresh token
        user: UserResponse {
            username: claims.username,
            role: claims.role,
        },
    };

    Ok(Json(response))
}

/*
    WS Connection Route
*/

#[get("/ws")]
async fn ws_handler(state: &State<AppState>) -> Result<(), rocket::http::Status> {
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

/*
    File Upload Routes
*/




/*
Getter Routes
*/



#[post("/api/get_load_info", format = "json", data = "<load_info_request>")]
async fn get_load_info(load_info_request: Json<LoadInfoRequest>, state: &State<AppState>, _user: AuthenticatedUser, role: Role) -> Result<Json<Vec<SidParts>>, Json<&'static str>> {
    if role.0 != "read" && role.0 != "write" {
        return Err(Json("Forbidden"));
    }

    let graph = &state.graph;
    let param = &load_info_request.param;

    let query = query("
        USE trucks MATCH (trailer:Trailer {id: $param})-[:HAS_SID]->(sid:SID)-[:HAS_PART]->(part:Part)
        RETURN sid, COLLECT({partNumber: part.number, quantity: part.quantity}) AS parts
    ").param("param", param.clone());

    match graph.execute(query).await {
        Ok(mut result) => {
            let mut data: Vec<SidParts> = Vec::new();
            while let Ok(Some(record)) = result.next().await {

                let sid_node: Node = record.get("sid").unwrap();
                let sid: String = sid_node.get("id").unwrap();
                let cisco: String = sid_node.get("ciscoID").unwrap();

                let SID: Sid = Sid {
                    CiscoID: cisco,
                    id: sid
                };

                let parts: Vec<Part> = record.get::<Vec<Part>>("parts")
                    .unwrap_or_else(|_| {
                        println!("Failed to extract parts");
                        Vec::new()
                    });
                
                let next: SidParts = SidParts { Sid: SID, Parts: parts };

                data.push(next);
            }
            Ok(Json(data))
        },
        Err(e) => {
            println!("Failed to run query: {:?}", e);
            Err(Json("Internal Server Error"))
        }
    }
}

#[post("/api/trailers", format = "json", data = "<date_request>")]
async fn trailers(date_request: Json<SidsRequest>, state: &State<AppState>, _user: AuthenticatedUser, role: Role) -> Result<Json<Vec<TrailerResponse>>, Json<&'static str>> {
    if role.0 != "read" && role.0 != "write" {
        return Err(Json("Forbidden"));
    }

    let graph = &state.graph;
    let date = &date_request.date;

    let query = query("
        USE trucks MATCH (trailer:Trailer)-[:HAS_SCHEDULE]->(s:Schedule {ScheduleDate: $date})
        MATCH (trailer)-[:HAS_SID]->(sid:SID)-[:HAS_PART]->(part:Part)
        RETURN trailer.id AS TrailerID, sid.id AS sid, sid.ciscoID AS cisco, part.number AS partNumber, part.quantity AS quantity
    ").param("date", date.clone());

    match graph.execute(query).await {
        Ok(mut result) => {

            let mut trailers_map: std::collections::HashMap<String, Vec<SidAndParts>> = std::collections::HashMap::new();
            while let Ok(Some(record)) = result.next().await {

                let trailer_id: String = record.get("TrailerID").unwrap();
                let sid: String = record.get("sid").unwrap();
                let cisco: String = record.get("cisco").unwrap();
                let part_number: String = record.get("partNumber").unwrap();
                let quantity: i32 = record.get("quantity").unwrap();
            
                let part = SidAndParts {
                    Sid: sid,
                    Cisco: cisco,
                    Quantity: quantity,
                    Part: part_number,
                };

                trailers_map.entry(trailer_id).or_insert(Vec::new()).push(part);

            }

            let trailers: Vec<TrailerResponse> = trailers_map.into_iter().map(|(trailer_id, parts)| TrailerResponse {
                TrailerID: trailer_id,
                Sids: parts,
            }).collect();

            Ok(Json(trailers))
        },
        Err(e) => {
            println!("Failed to run query: {:?}", e);
            Err(Json("Internal Server Error"))
        }
    }
}

#[get("/api/schedule_trailer")]
async fn schedule_trailer(state: &State<AppState>, _user: AuthenticatedUser, role: Role) -> Result<Json<Vec<Trailer>>, Json<&'static str>> {
    if role.0 != "write" && role.0 != "read" {
        return Err(Json("Forbidden"));
    }
    
    let graph = &state.graph;

    let query = query("
        USE trucks 
        MATCH (trailer:Trailer)-[:HAS_SCHEDULE]->(s:Schedule)
        WITH trailer, s
        MATCH (trailer)-[:HAS_CISCO]->(cisco:Cisco)
        RETURN trailer.id AS TrailerID, s, COLLECT(cisco.id) AS CiscoIDs
    ");

    match graph.execute(query).await {
        Ok(mut result) => {
            let mut data: Vec<Trailer> = Vec::new();
            while let Ok(Some(record)) = result.next().await {
                let trailer_id: String = record.get("TrailerID").unwrap();
                let schedule_node: Node = record.get("s").unwrap();
                let schedule_date: String = schedule_node.get("ScheduleDate").unwrap();
                let schedule_time: String = schedule_node.get("ScheduleTime").unwrap();
                let arrival_time: String = schedule_node.get("ArrivalTime").unwrap();
                let carrier_code: String = schedule_node.get("CarrierCode").unwrap();
                let contact_email: String = schedule_node.get("ContactEmail").unwrap();
                let door_number: String = schedule_node.get("DoorNumber").unwrap();
                let is_hot: bool = schedule_node.get("IsHot").unwrap();
                let last_free_date: String = schedule_node.get("LastFreeDate").unwrap_or("".to_string());
                let load_status: String = schedule_node.get("LoadStatus").unwrap();
                let request_date: String = schedule_node.get("RequestDate").unwrap();
                let cisco_ids: Vec<String> = record.get("CiscoIDs").unwrap();

                let trailer = Trailer {
                    TrailerID: trailer_id,
                    Schedule: Schedule {
                        ScheduleDate: schedule_date,
                        ScheduleTime: schedule_time,
                        ArrivalTime: arrival_time,
                        CarrierCode: carrier_code,
                        ContactEmail: contact_email,	
                        DoorNumber: door_number,
                        IsHot: is_hot,
                        LastFreeDate: last_free_date,
                        LoadStatus: load_status,
                        RequestDate: request_date,
                    },
                    CiscoIDs: cisco_ids,
                };

                data.push(trailer);
            }
            Ok(Json(data))
        },
        Err(e) => {
            println!("Failed to run query: {:?}", e);
            Err(Json("Internal Server Error"))
        }
    }
}

#[post("/api/todays_trucks", format = "json", data = "<todays_trucks_request>")]
async fn todays_trucks(
    todays_trucks_request: Json<TodaysTrucksRequest>,
    state: &State<AppState>,
    _user: AuthenticatedUser,
    role: Role,
) -> Result<Json<Vec<Trailer>>, Json<&'static str>> {
    if role.0 != "read" && role.0 != "write" {
        return Err(Json("Forbidden"));
    }

    let graph = &state.graph;

    let query = query("
        USE trucks MATCH (trailer:Trailer)-[:HAS_SCHEDULE]->(s:Schedule)
        WHERE s.ScheduleDate = $date
        WITH trailer, s
        MATCH (trailer)-[:HAS_CISCO]->(cisco:Cisco)
        RETURN trailer.id AS TrailerID, s, COLLECT(cisco.id) AS CiscoIDs
    ").param("date", todays_trucks_request.date.clone());

    match graph.execute(query).await {
        Ok(mut result) => {
            let mut data: Vec<Trailer> = Vec::new();
            while let Ok(Some(record)) = result.next().await {
                let trailer_id: String = record.get("TrailerID").unwrap();
                let schedule_node: Node = record.get("s").unwrap();
                let schedule_date: String = schedule_node.get("ScheduleDate").unwrap();
                let schedule_time: String = schedule_node.get("ScheduleTime").unwrap();
                let arrival_time: String = schedule_node.get("ArrivalTime").unwrap();
                let carrier_code: String = schedule_node.get("CarrierCode").unwrap();
                let contact_email: String = schedule_node.get("ContactEmail").unwrap();
                let door_number: String = schedule_node.get("DoorNumber").unwrap();
                let is_hot: bool = schedule_node.get("IsHot").unwrap();
                let last_free_date: String = schedule_node.get("LastFreeDate").unwrap();
                let load_status: String = schedule_node.get("LoadStatus").unwrap();
                let request_date: String = schedule_node.get("RequestDate").unwrap();
                let cisco_ids: Vec<String> = record.get("CiscoIDs").unwrap();

                let trailer = Trailer {
                    TrailerID: trailer_id,
                    Schedule: Schedule {
                        ScheduleDate: schedule_date,
                        ScheduleTime: schedule_time,
                        ArrivalTime: arrival_time,
                        CarrierCode: carrier_code,
                        ContactEmail: contact_email,	
                        DoorNumber: door_number,
                        IsHot: is_hot,
                        LastFreeDate: last_free_date,
                        LoadStatus: load_status,
                        RequestDate: request_date,
                    },
                    CiscoIDs: cisco_ids,
                };

                data.push(trailer);
            }
            Ok(Json(data))
        },
        Err(e) => {
            println!("Failed to run query: {:?}", e);
            Err(Json("Internal Server Error"))
        }
    }
}

#[post("/api/trucks_date_range", format = "json", data = "<date_range_trucks_request>")]
async fn date_range_trucks(
    date_range_trucks_request: Json<DateRangeTruckRequest>,
    state: &State<AppState>,
    _user: AuthenticatedUser,
    role: Role,
) -> Result<Json<Vec<Trailer>>, Json<&'static str>> {
    if role.0 != "read" && role.0 != "write" {
        return Err(Json("Forbidden"));
    }

    let graph = &state.graph;

    let query = query("
        USE trucks MATCH (trailer:Trailer)-[:HAS_SCHEDULE]->(s:Schedule)
        WHERE s.ScheduleDate >= $date1 and s.ScheduleDate <= $date2
        WITH trailer, s
        MATCH (trailer)-[:HAS_CISCO]->(cisco:Cisco)
        RETURN trailer.id AS TrailerID, s, COLLECT(cisco.id) AS CiscoIDs
    ").param("date1", date_range_trucks_request.date1.clone())
      .param("date2", date_range_trucks_request.date2.clone());

    match graph.execute(query).await {
        Ok(mut result) => {
            let mut data: Vec<Trailer> = Vec::new();
            while let Ok(Some(record)) = result.next().await {
                let trailer_id: String = record.get("TrailerID").unwrap();
                let schedule_node: Node = record.get("s").unwrap();
                let schedule_date: String = schedule_node.get("ScheduleDate").unwrap();
                let schedule_time: String = schedule_node.get("ScheduleTime").unwrap();
                let arrival_time: String = schedule_node.get("ArrivalTime").unwrap();
                let carrier_code: String = schedule_node.get("CarrierCode").unwrap();
                let contact_email: String = schedule_node.get("ContactEmail").unwrap();
                let door_number: String = schedule_node.get("DoorNumber").unwrap();
                let is_hot: bool = schedule_node.get("IsHot").unwrap();
                let last_free_date: String = schedule_node.get("LastFreeDate").unwrap();
                let load_status: String = schedule_node.get("LoadStatus").unwrap();
                let request_date: String = schedule_node.get("RequestDate").unwrap();
                let cisco_ids: Vec<String> = record.get("CiscoIDs").unwrap();

                let trailer = Trailer {
                    TrailerID: trailer_id,
                    Schedule: Schedule {
                        ScheduleDate: schedule_date,
                        ScheduleTime: schedule_time,
                        ArrivalTime: arrival_time,
                        CarrierCode: carrier_code,
                        ContactEmail: contact_email,	
                        DoorNumber: door_number,
                        IsHot: is_hot,
                        LastFreeDate: last_free_date,
                        LoadStatus: load_status,
                        RequestDate: request_date,
                    },
                    CiscoIDs: cisco_ids,
                };

                data.push(trailer);
            }
            Ok(Json(data))
        },
        Err(e) => {
            println!("Failed to run query: {:?}", e);
            Err(Json("Internal Server Error"))
        }
    }
}

/*
    Setter Routes
*/

#[post("/api/set_schedule", format = "json", data = "<schedule_request>")]
async fn set_schedule(
    schedule_request: Json<SetScheduleRequest>,
    state: &State<AppState>,
    _user: AuthenticatedUser,
    role: Role,
) -> Result<Json<Vec<TrailerSchedule>>, Json<&'static str>> {
    if role.0 != "write" {
        return Err(Json("Forbidden"));
    }

    let graph = &state.graph;

    let query = query("
        USE trucks MATCH (trailer:Trailer)-[:HAS_SCHEDULE]->(s:Schedule)
        WHERE trailer.id = $TrailerID
        SET s.ScheduleDate = $ScheduleDate,
            s.RequestDate = $RequestDate,
            s.CarrierCode = $CarrierCode,
            s.ScheduleTime = $ScheduleTime,
            s.LastFreeDate = $LastFreeDate,
            s.ContactEmail = $ContactEmail,
            s.DoorNumber = $Door
        RETURN trailer.id as TrailerID, s
    ")
    .param("TrailerID", schedule_request.TrailerID.clone())
    .param("ScheduleDate", schedule_request.ScheduleDate.clone())
    .param("RequestDate", schedule_request.RequestDate.clone())
    .param("CarrierCode", schedule_request.CarrierCode.clone())
    .param("ScheduleTime", schedule_request.ScheduleTime.clone())
    .param("LastFreeDate", schedule_request.LastFreeDate.clone())
    .param("ContactEmail", schedule_request.ContactEmail.clone())
    .param("Door", schedule_request.Door.clone());

    match graph.execute(query).await {
        Ok(mut result) => {
            let mut data: Vec<TrailerSchedule> = Vec::new();
            while let Ok(Some(record)) = result.next().await {

                let trailer_id: String = record.get("TrailerID").unwrap();
                let schedule_node: Node = record.get("s").unwrap();
                let schedule_date: String = schedule_node.get("ScheduleDate").unwrap();
                let schedule_time: String = schedule_node.get("ScheduleTime").unwrap();
                let arrival_time: String = schedule_node.get("ArrivalTime").unwrap();
                let carrier_code: String = schedule_node.get("CarrierCode").unwrap();
                let contact_email: String = schedule_node.get("ContactEmail").unwrap();
                let door_number: String = schedule_node.get("DoorNumber").unwrap();
                let is_hot: bool = schedule_node.get("IsHot").unwrap();
                let last_free_date: String = schedule_node.get("LastFreeDate").unwrap();
                let load_status: String = schedule_node.get("LoadStatus").unwrap();
                let request_date: String = schedule_node.get("RequestDate").unwrap();
                let schedule_data = TrailerSchedule {
                    TrailerID: trailer_id,
                    Schedule: Schedule {
                        ScheduleDate: schedule_date,
                        ScheduleTime: schedule_time,
                        ArrivalTime: arrival_time,
                        CarrierCode: carrier_code,
                        ContactEmail: contact_email,	
                        DoorNumber: door_number,
                        IsHot: is_hot,
                        LastFreeDate: last_free_date,
                        LoadStatus: load_status,
                        RequestDate: request_date,
                    },
                };
                data.push(schedule_data);
            }

            Ok(Json(data))
        },
        Err(e) => {
            println!("Failed to run query: {:?}", e);
            Err(Json("Internal Server Error"))
        }
    }
}

#[post("/api/hot_trailer", format = "json", data = "<hot_trailer_request>")]
async fn hot_trailer(
    hot_trailer_request: Json<HotTrailerRequest>,
    state: &State<AppState>,
    _user: AuthenticatedUser,
    role: Role,
) -> Result<Json<Vec<TrailerSchedule>>, Json<&'static str>> {
    if role.0 != "write" {
        return Err(Json("Forbidden"));
    }

    let graph = &state.graph;
    println!("{:?}", hot_trailer_request);

    let query = query("
        USE trucks MATCH (trailer:Trailer)-[:HAS_SCHEDULE]->(s:Schedule)
        WHERE trailer.id = $TrailerID
        SET s.IsHot = NOT s.IsHot  
        RETURN trailer.id as TrailerID, s
    ").param("TrailerID", hot_trailer_request.TrailerID.clone());

    match graph.execute(query).await {
        Ok(mut result) => {
            let mut data: Vec<TrailerSchedule> = Vec::new();
            while let Ok(Some(record)) = result.next().await {

                let trailer_id: String = record.get("TrailerID").unwrap();
                let schedule_node: Node = record.get("s").unwrap();
                let schedule_date: String = schedule_node.get("ScheduleDate").unwrap();
                let schedule_time: String = schedule_node.get("ScheduleTime").unwrap();
                let arrival_time: String = schedule_node.get("ArrivalTime").unwrap();
                let carrier_code: String = schedule_node.get("CarrierCode").unwrap();
                let contact_email: String = schedule_node.get("ContactEmail").unwrap();
                let door_number: String = schedule_node.get("DoorNumber").unwrap();
                let is_hot: bool = schedule_node.get("IsHot").unwrap();
                let last_free_date: String = schedule_node.get("LastFreeDate").unwrap();
                let load_status: String = schedule_node.get("LoadStatus").unwrap();
                let request_date: String = schedule_node.get("RequestDate").unwrap();
                let schedule_data = TrailerSchedule {
                    TrailerID: trailer_id,
                    Schedule: Schedule {
                        ScheduleDate: schedule_date,
                        ScheduleTime: schedule_time,
                        ArrivalTime: arrival_time,
                        CarrierCode: carrier_code,
                        ContactEmail: contact_email,	
                        DoorNumber: door_number,
                        IsHot: is_hot,
                        LastFreeDate: last_free_date,
                        LoadStatus: load_status,
                        RequestDate: request_date,
                    },
                };
                data.push(schedule_data);
            }

            Ok(Json(data))
        },
        Err(e) => {
            println!("Failed to run query: {:?}", e);
            Err(Json("Internal Server Error"))
        }
    }
}

#[post("/api/set_door", format = "json", data = "<set_door_request>")]
async fn set_door(
    set_door_request: Json<SetDoorRequest>,
    state: &State<AppState>,
    _user: AuthenticatedUser,
    role: Role,
) -> Result<Json<Vec<TrailerSchedule>>, Json<&'static str>> {
    if role.0 != "write" {
        return Err(Json("Forbidden"));
    }

    let graph = &state.graph;
    println!("{:?}", set_door_request);

    let query = query("
        USE trucks MATCH (trailer:Trailer)-[:HAS_SCHEDULE]->(s:Schedule)
        WHERE trailer.id = $TrailerID
        SET s.DoorNumber = $Door
        RETURN trailer.id as TrailerID, s
    ")
    .param("TrailerID", set_door_request.TrailerID.clone())
    .param("Door", set_door_request.Door.clone());

    match graph.execute(query).await {
        Ok(mut result) => {
            let mut data: Vec<TrailerSchedule> = Vec::new();
            while let Ok(Some(record)) = result.next().await {

                let trailer_id: String = record.get("TrailerID").unwrap();
                let schedule_node: Node = record.get("s").unwrap();
                let schedule_date: String = schedule_node.get("ScheduleDate").unwrap();
                let schedule_time: String = schedule_node.get("ScheduleTime").unwrap();
                let arrival_time: String = schedule_node.get("ArrivalTime").unwrap();
                let carrier_code: String = schedule_node.get("CarrierCode").unwrap();
                let contact_email: String = schedule_node.get("ContactEmail").unwrap();
                let door_number: String = schedule_node.get("DoorNumber").unwrap();
                let is_hot: bool = schedule_node.get("IsHot").unwrap();
                let last_free_date: String = schedule_node.get("LastFreeDate").unwrap();
                let load_status: String = schedule_node.get("LoadStatus").unwrap();
                let request_date: String = schedule_node.get("RequestDate").unwrap();
                let schedule_data = TrailerSchedule {
                    TrailerID: trailer_id,
                    Schedule: Schedule {
                        ScheduleDate: schedule_date,
                        ScheduleTime: schedule_time,
                        ArrivalTime: arrival_time,
                        CarrierCode: carrier_code,
                        ContactEmail: contact_email,	
                        DoorNumber: door_number,
                        IsHot: is_hot,
                        LastFreeDate: last_free_date,
                        LoadStatus: load_status,
                        RequestDate: request_date,
                    },
                };
                data.push(schedule_data);
            }

            Ok(Json(data))
        },
        Err(e) => {
            println!("Failed to run query: {:?}", e);
            Err(Json("Internal Server Error"))
        }
    }
}

#[post("/api/set_arrivalTime", format = "json", data = "<set_arrival_time_request>")]
async fn set_arrival_time(
    set_arrival_time_request: Json<SetArrivalTimeRequest>,
    state: &State<AppState>,
    _user: AuthenticatedUser,
    role: Role,
) -> Result<Json<Vec<TrailerSchedule>>, Json<&'static str>> {
    if role.0 != "write" {
        return Err(Json("Forbidden"));
    }

    let graph = &state.graph;
    println!("{:?}", set_arrival_time_request);

    let query = query("
        USE trucks MATCH (trailer:Trailer)-[:HAS_SCHEDULE]->(s:Schedule)
        WHERE trailer.id = $TrailerID
        SET s.ArrivalTime = $ArrivalTime
        RETURN trailer.id as TrailerID, s
    ")
    .param("TrailerID", set_arrival_time_request.TrailerID.clone())
    .param("ArrivalTime", set_arrival_time_request.ArrivalTime.clone());

    match graph.execute(query).await {
        Ok(mut result) => {
            let mut data: Vec<TrailerSchedule> = Vec::new();
            while let Ok(Some(record)) = result.next().await {

                let trailer_id: String = record.get("TrailerID").unwrap();
                let schedule_node: Node = record.get("s").unwrap();
                let schedule_date: String = schedule_node.get("ScheduleDate").unwrap();
                let schedule_time: String = schedule_node.get("ScheduleTime").unwrap();
                let arrival_time: String = schedule_node.get("ArrivalTime").unwrap();
                let carrier_code: String = schedule_node.get("CarrierCode").unwrap();
                let contact_email: String = schedule_node.get("ContactEmail").unwrap();
                let door_number: String = schedule_node.get("DoorNumber").unwrap();
                let is_hot: bool = schedule_node.get("IsHot").unwrap();
                let last_free_date: String = schedule_node.get("LastFreeDate").unwrap();
                let load_status: String = schedule_node.get("LoadStatus").unwrap();
                let request_date: String = schedule_node.get("RequestDate").unwrap();
                let schedule_data = TrailerSchedule {
                    TrailerID: trailer_id,
                    Schedule: Schedule {
                        ScheduleDate: schedule_date,
                        ScheduleTime: schedule_time,
                        ArrivalTime: arrival_time,
                        CarrierCode: carrier_code,
                        ContactEmail: contact_email,	
                        DoorNumber: door_number,
                        IsHot: is_hot,
                        LastFreeDate: last_free_date,
                        LoadStatus: load_status,
                        RequestDate: request_date,
                    },
                };

                data.push(schedule_data);
            }

            Ok(Json(data))
        },
        Err(e) => {
            println!("Failed to run query: {:?}", e);
            Err(Json("Internal Server Error"))
        }
    }
}

/*
    CORS Config
*/

fn is_allowed_origin(origin: &str) -> bool {
    // Parse the origin to extract the IP address
    if let Ok(url) = url::Url::parse(origin) {
        if let Some(host) = url.host_str() {
            if let Ok(ip) = host.parse::<IpAddr>() {
                // Define the allowed IP range
                let allowed_range_start = "192.168.4.1".parse::<IpAddr>().unwrap();
                let allowed_range_end = "192.168.4.255".parse::<IpAddr>().unwrap();
                
                return ip >= allowed_range_start && ip <= allowed_range_end;
            }
        }
    }
    false
}

fn custom_cors() -> rocket_cors::Cors {
    CorsOptions::default()
        .allowed_origins(rocket_cors::AllOrSome::All)
        .allowed_headers(AllowedHeaders::some(&["Authorization", "Accept", "Content-Type"]))
        .allow_credentials(true)
        .to_cors()
        .expect("error creating CORS fairing")
}

impl AppState {
    pub async fn new() -> Self {
        let graph = Graph::new("bolt://localhost:7687", "neo4j", "Asdf123$").await.unwrap();

        AppState {
            ws_list: Arc::new(Mutex::new(HashMap::new())),
            graph: Arc::new(graph),
            jwt_secret: "tO7E8uCjD5rXpQl0FhKwV2yMz4bJnAi9sGeR3kTzXvNmPuLsDq8W".to_string(),
        }
    }
}

#[rocket::main]
async fn main() {
    let state = AppState::new().await;

    let figment = rocket::Config::figment()
        .merge(("tls.certs", "/usr/local/share/ca-certificates/server.crt"))
        .merge(("tls.key", "certs/server.key"))
        .merge(("port", 8443));
    // Configure CORS
    let cors = custom_cors();

    rocket::custom(
        figment
    )
        .attach(cors)
        .mount("/", routes![todays_trucks, date_range_trucks, set_arrival_time, set_door, hot_trailer, set_schedule, get_load_info, trailers, ws_handler, refresh_token, login, schedule_trailer, register])
        .manage(state)
        .launch()
        .await
        .unwrap();
}