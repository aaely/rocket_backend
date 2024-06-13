#[macro_use] extern crate rocket;

mod auth;
mod role;

use jsonwebtoken::{encode, Header, EncodingKey};
use rocket::{get, post, routes, serde::json::Json, State};
use neo4rs::{Graph, query, Node, ConfigBuilder};
use tokio::sync::Mutex;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use auth::AuthenticatedUser;
use role::Role;
use bcrypt::{hash, verify, DEFAULT_COST};

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    user: UserResponse,
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

#[derive(Serialize, Deserialize)]
struct Trailer {
    TrailerID: String,
    Schedule: Schedule,
    CiscoIDs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
struct Parts {
    Quantity: u8,
    PartNumber: String,
}

struct AppState {
    graph: Arc<Graph>,
    jwt_secret: String,
}

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
            let token = match encode(
                &Header::default(),
                &UserResponse { username: username.clone(), role: role.clone() },
                &EncodingKey::from_secret(state.jwt_secret.as_ref()),
            ) {
                Ok(t) => t,
                Err(e) => return Err(Json(e.to_string())),
            };

            let response = LoginResponse {
                token,
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

#[get("/test")]
async fn test(state: &State<AppState>, _user: AuthenticatedUser) -> Result<Json<Vec<String>>, Json<&'static str>> {
    let graph = &state.graph;

    let query = query("
        USE trucks
        MATCH (trailer:Trailer) RETURN trailer.id as TrailerID LIMIT 5
    ");

    match graph.execute(query).await {
        Ok(mut result) => {
            let mut data: Vec<String> = Vec::new();
            while let Ok(Some(record)) = result.next().await {
                let trailer_id: String = record.get("TrailerID").unwrap();
                println!("Trailer: {}", trailer_id);
                data.push(trailer_id);
            }
            Ok(Json(data))
        }
        Err(e) => {
            println!("Failed to run query: {:?}", e);
            Err(Json("Internal Server Error"))
        }
    }
}

#[get("/api/schedule_trailer")]
async fn schedule_trailer(state: &State<AppState>, _user: AuthenticatedUser) -> Result<Json<Vec<Trailer>>, Json<&'static str>> {
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


#[rocket::main]
async fn main() {
    let graph = Arc::new(
        Graph::new("bolt://localhost:7687", "neo4j", "Asdf123$").await.unwrap()
    );

    let state = AppState {
        graph,
        jwt_secret: "tO7E8uCjD5rXpQl0FhKwV2yMz4bJnAi9sGeR3kTzXvNmPuLsDq8W".to_string(),
    };

    rocket::build()
        .mount("/", routes![login, test, schedule_trailer, register])
        .manage(state)
        .launch()
        .await
        .unwrap();
}