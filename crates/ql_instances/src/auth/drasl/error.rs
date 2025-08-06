use ql_core::{JsonError, RequestError};
use serde::Deserialize;

use crate::auth::KeyringError;

#[derive(Deserialize, Clone, Debug)]
#[allow(non_snake_case)]
pub struct AccountResponseError {
    pub error: String,
    pub errorMessage: String,
}

impl std::error::Error for AccountResponseError {}
impl std::fmt::Display for AccountResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error, self.errorMessage)
    }
}

const AUTH_ERR_PREFIX: &str = "while logging into yggdrasil account:\n";
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{AUTH_ERR_PREFIX}{0}")]
    Request(#[from] RequestError),
    #[error("{AUTH_ERR_PREFIX}{0}")]
    Json(#[from] JsonError),
    #[error("{AUTH_ERR_PREFIX}\n{0}")]
    Response(#[from] AccountResponseError),
    #[error("{AUTH_ERR_PREFIX}\n{0}")]
    KeyringError(#[from] KeyringError),
    // idk about these macro things hope this is ok
    #[error("{AUTH_ERR_PREFIX}\n{0}")]
    InvalidResponse(InvaildResponse),
    #[error("{AUTH_ERR_PREFIX}\n{0}")]
    InputError(DrasilInputError),
}

#[derive(Debug)]
pub enum DrasilInputError {
    // the url provided by the user can not be parsed into a valid reqwest url
    CantParseUrl(String), // we need the url crate's ParseError to expand this with a proper type
}

#[derive(Debug)]
pub enum InvaildResponse {
    MissingProfile,
}

impl std::error::Error for InvaildResponse {}
impl std::fmt::Display for InvaildResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid Response from server: {}", self)
    }
}

impl std::error::Error for DrasilInputError {}
impl std::fmt::Display for DrasilInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid Response from server: {}", self)
    }
}

impl From<ql_reqwest::Error> for Error {
    fn from(value: ql_reqwest::Error) -> Self {
        Self::Request(RequestError::ReqwestError(value))
    }
}

impl From<keyring::Error> for Error {
    fn from(err: keyring::Error) -> Self {
        Self::KeyringError(KeyringError(err))
    }
}
