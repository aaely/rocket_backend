use crate::structs::*;
use crate::auth::AuthenticatedUser;
use crate::role::Role;
use rocket::{post, serde::json::Json, State};
use neo4rs::{query, Node};

#[post("/api/set_schedule", format = "json", data = "<schedule_request>")]
pub async fn set_schedule(
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
pub async fn hot_trailer(
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
pub async fn set_door(
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
pub async fn set_arrival_time(
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