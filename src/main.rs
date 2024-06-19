extern crate rocket;

mod auth;
mod role;
mod structs;
mod getters;
mod setters;
mod loginroutes;
mod wsserver;

use rocket::routes;
use neo4rs::Graph;
use tokio::sync::Mutex;
use std::{collections::HashMap, sync::Arc};
use rocket_cors::{CorsOptions, AllowedHeaders};
use structs::*;
use getters::*;
use setters::*;
use loginroutes::*;
use wsserver::*;


/*
    CORS Config
*/

/*fn is_allowed_origin(origin: &str) -> bool {
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
}*/

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