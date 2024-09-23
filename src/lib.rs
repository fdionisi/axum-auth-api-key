mod api_key_header;

use std::convert::Infallible;

use api_key_header::ApiKeyHeader;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::TypedHeader;

#[derive(Clone)]
pub struct ApiKey(String);

impl From<String> for ApiKey {
    fn from(key: String) -> Self {
        Self(key)
    }
}

pub async fn auth_middleware(
    State(ApiKey(token)): State<ApiKey>,
    TypedHeader(authorization): TypedHeader<ApiKeyHeader>,
    request: Request,
    next: Next,
) -> Result<Response, Infallible> {
    if authorization.key() != token {
        return Ok((StatusCode::UNAUTHORIZED, "Unauthorized").into_response());
    }

    Ok(next.run(request).await)
}
