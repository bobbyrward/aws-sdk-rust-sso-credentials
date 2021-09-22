use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aws_config::default_provider::credentials::default_provider;
use aws_config::meta::credentials::{CredentialsProviderChain, LazyCachingCredentialsProvider};
use aws_types::credentials::{Credentials, CredentialsError, ProvideCredentials};
use aws_types::os_shim_internal::{Env, Fs};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub enum SSOProviderError {
    RequiredConfigMissing(String),
}

impl std::fmt::Display for SSOProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequiredConfigMissing(field) => {
                write!(f, "SSOProviderError: Missing required config: {}", field)
            }
        }
    }
}

impl std::error::Error for SSOProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        unimplemented!()
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }
}

#[derive(Clone, Default)]
struct SSOProviderState {
    sso_config: Option<SSOConfig>,
    cached_token: Option<CachedSSOToken>,
}

#[derive(Clone, Default)]
pub struct SSOProvider {
    state: Arc<Mutex<SSOProviderState>>,
}

impl SSOProvider {
    pub fn new() -> Self {
        Default::default()
    }

    pub async fn chained() -> LazyCachingCredentialsProvider {
        LazyCachingCredentialsProvider::builder()
            .load(
                CredentialsProviderChain::first_try("sso", Self::new())
                    .or_else("default", default_provider().await),
            )
            .build()
    }
}

impl std::fmt::Debug for SSOProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SSOProvider").finish()
    }
}

impl ProvideCredentials for SSOProvider {
    fn provide_credentials<'a>(&'a self) -> aws_types::credentials::future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        let inner_state = self.state.clone();

        aws_types::credentials::future::ProvideCredentials::new(do_provider_credentials(
            inner_state,
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CachedSSOToken {
    access_token: String,
    expires_at: DateTime<Utc>,
    region: String,
    start_url: String,
}

#[derive(Clone, Default, Debug)]
struct SSOConfig {
    sso_account_id: String,
    sso_role_name: String,
    sso_region: String,
    sso_start_url: String,
}

async fn do_provider_credentials(
    state: Arc<Mutex<SSOProviderState>>,
) -> Result<Credentials, CredentialsError> {
    let mut state = state.lock().await;

    if state.sso_config.is_none() {
        state.sso_config = Some(load_sso_config().await?);
    }

    if let Some(token) = &state.cached_token {
        if token.expires_at <= Utc::now() {
            state.cached_token = None;
        }
    }

    if state.cached_token.is_none() {
        state.cached_token =
            load_token_file(&state.sso_config.as_ref().unwrap().sso_start_url).await;
    }

    if state.cached_token.is_none() {
        return Err(CredentialsError::CredentialsNotLoaded);
    }

    let config = aws_sdk_sso::Config::builder()
        .region(aws_sdk_sso::Region::new(Cow::Owned(
            state.sso_config.as_ref().unwrap().sso_region.to_owned(),
        )))
        .build();

    let client = aws_sdk_sso::Client::from_conf(config);

    if let Some(role_credentials) = client
        .get_role_credentials()
        .account_id(&state.sso_config.as_ref().unwrap().sso_account_id)
        .role_name(&state.sso_config.as_ref().unwrap().sso_role_name)
        .access_token(&state.cached_token.as_ref().unwrap().access_token)
        .send()
        .await
        .map_err(|e| CredentialsError::ProviderError(Box::new(e)))?
        .role_credentials
    {
        let expiration = Utc.timestamp(role_credentials.expiration, 0);

        return Ok(Credentials::new(
            role_credentials.access_key_id.ok_or_else(|| {
                CredentialsError::Unhandled(Box::new(SSOProviderError::RequiredConfigMissing(
                    "access_key_id".to_owned(),
                )))
            })?,
            role_credentials.secret_access_key.ok_or_else(|| {
                CredentialsError::Unhandled(Box::new(SSOProviderError::RequiredConfigMissing(
                    "secret_access_key".to_owned(),
                )))
            })?,
            Some(role_credentials.session_token.ok_or_else(|| {
                CredentialsError::Unhandled(Box::new(SSOProviderError::RequiredConfigMissing(
                    "session_token".to_owned(),
                )))
            })?),
            Some(expiration.into()),
            "sso",
        ));
    }

    Err(CredentialsError::CredentialsNotLoaded)
}

async fn load_sso_config() -> Result<SSOConfig, CredentialsError> {
    let fs = Fs::default();
    let env = Env::default();

    let profile_set = aws_config::profile::load(&fs, &env)
        .await
        .map_err(|_| CredentialsError::CredentialsNotLoaded)?;

    if profile_set.is_empty() {
        return Err(CredentialsError::CredentialsNotLoaded);
    }

    if let Some(sso_account_id) = profile_set.get("sso_account_id") {
        if let Some(sso_role_name) = profile_set.get("sso_role_name") {
            if let Some(sso_region) = profile_set.get("sso_region") {
                if let Some(sso_start_url) = profile_set.get("sso_start_url") {
                    return Ok(SSOConfig {
                        sso_account_id: sso_account_id.to_owned(),
                        sso_role_name: sso_role_name.to_owned(),
                        sso_region: sso_region.to_owned(),
                        sso_start_url: sso_start_url.to_owned(),
                    });
                }
            }
        }
    }

    Err(CredentialsError::CredentialsNotLoaded)
}

async fn load_token_file(start_url: &str) -> Option<CachedSSOToken> {
    let mut filename = default_cache_location();

    filename.push(get_cache_filename(start_url));

    tokio::fs::read_to_string(&filename)
        .await
        .ok()
        .and_then(|contents| serde_json::from_str::<CachedSSOToken>(&contents).ok())
        .and_then(|cached_token| {
            if cached_token.access_token.is_empty() {
                None
            } else {
                Some(cached_token)
            }
        })
        .and_then(|cached_token| {
            if cached_token.expires_at <= Utc::now() {
                None
            } else {
                Some(cached_token)
            }
        })
}

fn default_cache_location() -> PathBuf {
    IntoIterator::into_iter([
        dirs::home_dir().expect("Need to have a home dir").as_ref(),
        Path::new(".aws"),
        Path::new("sso"),
        Path::new("cache"),
    ])
    .collect()
}

fn get_cache_filename(start_url: &str) -> String {
    hex::encode(Sha1::digest(start_url.as_bytes())) + ".json"
}
