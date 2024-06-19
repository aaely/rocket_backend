use crate::structs::*;
use crate::auth::{AuthenticatedUser, decode_token, Claims};
use crate::role::Role;
use rocket::{get, post, response::status::BadRequest, routes, serde::json::Json, State};
use neo4rs::{query, Node};


#[post("/api/get_load_info", format = "json", data = "<load_info_request>")]
pub async fn get_load_info(load_info_request: Json<LoadInfoRequest>, state: &State<AppState>, _user: AuthenticatedUser, role: Role) -> Result<Json<Vec<SidParts>>, Json<&'static str>> {
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
pub async fn trailers(date_request: Json<SidsRequest>, state: &State<AppState>, _user: AuthenticatedUser, role: Role) -> Result<Json<Vec<TrailerResponse>>, Json<&'static str>> {
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
pub async fn schedule_trailer(state: &State<AppState>, _user: AuthenticatedUser, role: Role) -> Result<Json<Vec<Trailer>>, Json<&'static str>> {
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
pub async fn todays_trucks(
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
pub async fn date_range_trucks(
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