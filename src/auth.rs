use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::http::Status;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    sub: String,
    pub role: String,
    exp: usize,
}

pub fn decode_token(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);
    decode::<Claims>(token, &key, &validation).map(|data| data.claims)
}

pub struct AuthenticatedUser(pub Claims);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let secret = "tO7E8uCjD5rXpQl0FhKwV2yMz4bJnAi9sGeR3kTzXvNmPuLsDq8W"; // Replace with your secret key
        if let Some(auth_header) = request.headers().get_one("Authorization") {
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                match decode_token(token, secret) {
                    Ok(claims) => return Outcome::Success(AuthenticatedUser(claims)),
                    Err(_) => return Outcome::Error((Status::Unauthorized, ())),
                }
            }
        }
        Outcome::Error((Status::Unauthorized, ()))
    }
}