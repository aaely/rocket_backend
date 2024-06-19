use crate::structs::*;
use crate::auth::{decode_token, Claims};
use rocket::{post, serde::json::Json, State};
use neo4rs::{query, Node};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, Header, EncodingKey};



#[post("/login", format = "json", data = "<login_request>")]
pub async fn login(login_request: Json<LoginRequest>, state: &State<AppState>) -> Result<Json<LoginResponse>, Json<String>> {
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
pub async fn register(user: Json<LoginRequest>, state: &State<AppState>) -> Result<Json<&'static str>, String> {
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
pub async fn refresh_token(refresh_request: Json<RefreshRequest>, state: &State<AppState>) -> Result<Json<LoginResponse>, Json<String>> {
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