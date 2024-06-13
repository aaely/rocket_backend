use rocket::request::{FromRequest, Outcome, Request};
use rocket::http::Status;
use crate::auth::AuthenticatedUser;

pub struct Role(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Role {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Outcome::Success(auth_user) = request.guard::<AuthenticatedUser>().await {
            let role = auth_user.0.role.clone();
            return Outcome::Success(Role(role));
        }
        Outcome::Error((Status::Forbidden, ()))
    }
}