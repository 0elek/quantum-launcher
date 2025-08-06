pub mod authlib;
pub mod error;

pub use error::{DrasilInputError, Error};
use ql_core::{err, info, pt, IntoJsonError, IntoStringError, RequestError, CLIENT};
use ql_reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::auth::{elyby::AccountResponseError, AccountData};

use super::get_keyring_entry;
pub use authlib::get_authlib_injector;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YggdrasilProvider {
    /// location of the auth server
    pub url: Url,
}

impl YggdrasilProvider {
    pub fn parse(url: &str) -> Result<Self, DrasilInputError> {
        let parsed_url =
            Url::parse(url.trim()).map_err(|e| DrasilInputError::CantParseUrl(e.to_string()))?;
        if parsed_url.has_host() == false {
            // the user entered a relative url, are they stupid
            return Err(DrasilInputError::CantParseUrl(
                "Url must have a host for example: https://example.com/authenticate".to_string(),
            ));
        }
        Ok(Self { url: parsed_url })
    }

    pub fn domain(&self) -> String {
        self.url.host_str().unwrap().to_string()
    }

    pub fn logout(&self, username: &str) -> Result<(), String> {
        // todo invalidate access token
        let entry = get_keyring_entry(&username, &self.domain()).strerr()?;
        if let Err(err) = entry.delete_credential() {
            err!(
                "Couldn't remove {} account credential (Username: {username}):\n{err}",
                self.domain()
            );
        }
        Ok(())
    }

    pub async fn login_refresh(&self, account_data: &AccountData) -> Result<AccountData, Error> {
        let username = &account_data.username;
        let refresh_token = &account_data.refresh_token;
        let client_id = &account_data.client_token;

        pt!("Refreshing {} account...", self.domain());

        let entry = get_keyring_entry(username, &self.domain())?;

        let response = CLIENT
            .post(self.url.join("refresh").unwrap())
            .json(&serde_json::json!({
                "accessToken": refresh_token,
                "clientToken": client_id
            }))
            .send()
            .await?;

        println!("{:?}", response);

        let text = if response.status().is_success() {
            response.text().await?
        } else {
            return Err(RequestError::DownloadError {
                code: response.status(),
                url: response.url().clone(),
            }
            .into());
        };

        let account_response = serde_json::from_str::<LoginResponse>(&text).json(text.clone())?;
        let selected_profile = account_response
            .selected_profile
            .ok_or_else(|| Error::InvalidResponse(error::InvaildResponse::MissingProfile))?;

        entry.set_password(&account_response.access_token)?;

        let mut account_data = account_data.clone();
        account_data.access_token = Some(account_response.access_token.clone());
        account_data.client_token = account_response.client_token;
        account_data.uuid = selected_profile.id;
        account_data.nice_username = selected_profile.name;
        account_data.refresh_token = account_response.access_token;
        account_data.needs_refresh = false;

        Ok(account_data.clone())
    }

    pub async fn invalidate(&self, account_data: &mut AccountData) -> Result<(), Error> {
        let access_token = account_data.access_token.clone().ok_or_else(|| {
            Error::KeyringError(crate::auth::KeyringError(keyring::Error::NoEntry))
        })?;

        let response = CLIENT
            .post(self.url.join("invalidate").unwrap())
            .json(&serde_json::json!({
                "agent":{
                    "name": "Minecraft",
                    "version": 1,
                },
                "accessToken": access_token,
                "clientToken": account_data.client_token,
                "requestUser": true
            }))
            .send()
            .await?;

        // if success then the body is empty
        if response.status().is_success() {
            Ok(())
        } else {
            let text = response.text().await?;
            if let Ok(res_err) =
                serde_json::from_str::<error::AccountResponseError>(&text).json(text)
            {
                return Err(Error::Response(res_err));
            } else {
                // TODO we need a new error type?
                return Err(Error::Response(error::AccountResponseError {
                    error: "Cant parse unsuccessful response".into(),
                    errorMessage: "cant parse Error into AccountResponseError".into(),
                }));
            }
        }
    }

    pub async fn login_new(
        url: String,
        username: String,
        password: String,
    ) -> Result<AccountData, Error> {
        let provider = YggdrasilProvider::parse(&url).unwrap();
        info!("Logging into {} account... ({username})", provider.domain());

        let payload = serde_json::json!({
            "agent": {
                "name": "Minecraft",
                "version": 1
            },
            "username": username,
            "password": password,
            // TODO we leave this empty so the server sends us a random one
            // but idealy we should generate these as a random v4 uuid
            // "clientToken": ,
            "requestUser": true
        });

        let response = CLIENT
            // this is safe, join only fails if the arg str is invalid
            .post(provider.url.join("authenticate").unwrap())
            .json(&payload)
            .send()
            .await?;

        let text = if response.status().is_success() {
            response.text().await?
        } else {
            return Err(RequestError::DownloadError {
                code: response.status(),
                url: response.url().clone(),
            }
            .into());
        };

        let account_response = match serde_json::from_str::<LoginResponse>(&text).json(text.clone())
        {
            Ok(n) => n,
            Err(err) => {
                if let Ok(res_err) = serde_json::from_str::<AccountResponseError>(&text).json(text)
                {
                    return Err(res_err.into());
                } else {
                    return Err(err.into());
                }
            }
        };
        let selected_profile = account_response
            .selected_profile
            .ok_or_else(|| Error::InvalidResponse(error::InvaildResponse::MissingProfile))?;

        let entry = get_keyring_entry(&username, &provider.domain())?;
        entry.set_password(&account_response.access_token)?;

        Ok(AccountData {
            access_token: Some(account_response.access_token.clone()),
            client_token: account_response.client_token,
            uuid: selected_profile.id,
            refresh_token: account_response.access_token,
            needs_refresh: false,
            username: username,
            nice_username: selected_profile.name,
            account_type: crate::auth::AccountType::Yggdrasil(provider.clone()),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub(crate) access_token: String,
    pub client_token: String,
    pub selected_profile: Option<SelectedProfile>,
    // user: User
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedProfile {
    pub id: String,
    pub name: String,
}

// #[derive(Clone, Clone, Deserialize)]
// #[serde(rename_all = "camelCase")]
// pub struct UserProp {
//     name: String,
//     value: String,
// }

// #[derive(Clone, Debug, Deserialize)]
// #[serde(rename_all = "camelCase")]
// pub struct User {
//     /// uuid
//     id: String,
//     properties: Vec<UserProp>,
// }Clone,
