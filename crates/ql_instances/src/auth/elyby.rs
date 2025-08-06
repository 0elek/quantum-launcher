use super::drasl::{error::InvaildResponse, LoginResponse};
use super::{get_keyring_entry, AccountData, YggdrasilProvider};
use ql_core::{info, IntoJsonError, RequestError, CLIENT};
use ql_reqwest::Url;

pub fn get_elyby_provider() -> YggdrasilProvider {
    let url = Url::parse("https://authserver.ely.by/auth/authenticate").unwrap();

    YggdrasilProvider {
        url,
    }
}

pub use super::drasl::{
    error::{AccountResponseError, Error},
    get_authlib_injector,
};

pub async fn login_new(email: String, password: String) -> Result<Account, Error> {
    // NOTE: It says email, but both username and email are accepted

    info!("Logging into ()... ({email})",);
    let response = CLIENT
        .post("https://authserver.ely.by/auth/authenticate")
        .json(&serde_json::json!({
            "username": &email,
            "password": &password,
            // "clientToken":
        }))
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

    let account_response = match serde_json::from_str::<LoginResponse>(&text).json(text.clone()) {
        Ok(n) => n,
        Err(err) => {
            if let Ok(res_err) = serde_json::from_str::<AccountResponseError>(&text).json(text) {
                if res_err.error == "ForbiddenOperationException"
                    && res_err.errorMessage == "Account protected with two factor auth."
                {
                    return Ok(Account::NeedsOTP);
                } else {
                    return Err(err.into());
                }
            } else {
                return Err(err.into());
            }
        }
    };
    let selected_profile = account_response
        .selected_profile
        .ok_or_else(|| Error::InvalidResponse(InvaildResponse::MissingProfile))?;

    let entry = get_keyring_entry(&email, &get_elyby_provider().domain())?;
    entry.set_password(&account_response.access_token)?;

    Ok(Account::Account(AccountData {
        access_token: Some(account_response.access_token.clone()),
        uuid: selected_profile.id,
        // we dont send a client token to the server so it should generates
        // a random one for us
        client_token: account_response.client_token,

        username: email,
        nice_username: selected_profile.name,

        refresh_token: account_response.access_token,
        needs_refresh: false,
        account_type: super::AccountType::ElyBy,
    }))
}

#[derive(Debug, Clone)]
pub enum Account {
    Account(AccountData),
    NeedsOTP,
}
