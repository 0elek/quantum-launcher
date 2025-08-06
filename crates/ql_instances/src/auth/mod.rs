pub mod drasl;
pub mod elyby;
pub mod ms;

use drasl::YggdrasilProvider;
use elyby::Error;
use std::fmt::Display;

#[derive(Debug, Clone)]
pub enum AccountType {
    Microsoft,
    ElyBy,
    Yggdrasil(YggdrasilProvider),
}

#[derive(Debug, Clone)]
pub struct AccountData {
    pub access_token: Option<String>,
    // aka client id
    pub client_token: String,
    pub uuid: String,
    pub refresh_token: String,
    pub needs_refresh: bool,

    pub username: String,
    pub nice_username: String,

    pub account_type: AccountType,
}

impl AccountData {
    pub fn get_username_modified(&self) -> String {
        let suffix = match &self.account_type {
            AccountType::Microsoft => "",
            AccountType::ElyBy => " (elyby)",
            AccountType::Yggdrasil(provider) => {
                &format!(" ({})", provider.url.to_string().to_string())
            }
        };
        format!("{}{suffix}", self.username)
    }
}
impl std::fmt::Display for AccountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AccountType::Microsoft => "Microsoft",
                AccountType::ElyBy => "ElyBy",
                AccountType::Yggdrasil(_provider) => "Drasl",
            }
        )
    }
}

impl AccountData {
    #[must_use]
    pub fn is_elyby(&self) -> bool {
        let account_type = &self.account_type;
        matches!(account_type, AccountType::ElyBy)
    }
}

#[derive(Debug, thiserror::Error)]
pub struct KeyringError(pub keyring::Error);

impl Display for KeyringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Account keyring error:")?;
        match &self.0 {
            #[cfg(target_os = "linux")]
            keyring::Error::PlatformFailure(error)
                if error.to_string().contains("The name is not activatable") =>
            {
                write!(f, "{error}\n\nTry installing gnome-keyring and libsecret packages\n(may be called differently depending on your distro)")
            }
            #[cfg(target_os = "linux")]
            keyring::Error::NoStorageAccess(error)
                if error.to_string().contains("no result found") =>
            {
                write!(
                    f,
                    r#"{error}

Install the "seahorse" app and open it,
Check for "Login" in the sidebar.
If it's there, make sure it's unlocked (right-click -> Unlock)

If it's not there, click on + then "Password Keyring",
and name it "Login" and put your preferred password

Now after this, in the sidebar, right click it and click "Set as Default""#
                )
            }

            _ => write!(f, "{}", self.0),
        }
    }
}

fn get_keyring_entry(username: &str, provider_domain: &str) -> Result<keyring::Entry, Error> {
    Ok(keyring::Entry::new(
        "QuantumLauncher",
        &format!("{username}#{}", provider_domain.replace('.', "_")),
    )?)
}

pub fn read_refresh_token(username: &str, provider_domain: &str) -> Result<String, Error> {
    let entry = get_keyring_entry(username, provider_domain)?;
    Ok(entry.get_password()?)
}
