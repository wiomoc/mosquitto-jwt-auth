extern crate base64;
extern crate jsonwebtoken;
#[macro_use]
extern crate serde_derive;

use crate::mosquitto_sys::{AclType, ClientID};
use crate::topic_utils::TopicPath;
use jsonwebtoken::{Algorithm, Validation};
use std::collections::HashMap;
use std::env;
use std::str::FromStr;

pub mod mosquitto_sys;
mod topic_utils;

struct MosquittoJWTAuthPluginConfig {
    secret: Vec<u8>,
    validation: Validation,
    validate_sub_match_username: bool,
}

impl MosquittoJWTAuthPluginConfig {
    fn from_opts(opts: HashMap<&str, &str>) -> Result<MosquittoJWTAuthPluginConfig, &'static str> {
        let alg = Algorithm::from_str(opts.get("jwt_alg").ok_or("'auth_opt_jwt_alg' is missing")?)
            .map_err(|_| "'auth_opt_jwt_alg' is not a valid jwt alg")?;

        let mut secret = None;

        if let Some(secret_env_opt) = opts.get("jwt_sec_env") {
            if let Ok(secret_base64) = env::var(secret_env_opt) {
                secret = Some(base64::decode(&secret_base64).map_err(|_| "invalid base64")?);
            }
        }

        if let Some(secret_opt) = opts.get("jwt_sec_base64") {
            if secret.is_none() {
                secret = Some(base64::decode(secret_opt).map_err(|_| "invalid base64")?);
            }
        }

        let secret = secret.ok_or("jwt_sec_env or jwt_sec_base64 missing")?;

        let validate_exp = if let Some(opt) = opts.get("jwt_validate_exp") {
            opt.parse::<bool>().map_err(|_| "'auth_opt_jwt_validate_exp' is not a boolean")?
        } else {
            true
        };

        let validate_sub_match_username = if let Some(opt) = opts.get("validate_sub_match_username")
        {
            opt.parse::<bool>().map_err(|_| "'auth_opt_validate_sub_match_username' is not a boolean")?
        } else {
            true
        };

        let validation = Validation {
            leeway: 0,
            validate_exp,
            validate_nbf: false,
            aud: None,
            iss: None,
            sub: None,
            algorithms: vec![alg],
        };

        Ok(MosquittoJWTAuthPluginConfig {
            secret,
            validation,
            validate_sub_match_username,
        })
    }
}

pub(crate) struct MosquittoJWTAuthPluginInstance {
    config: Option<MosquittoJWTAuthPluginConfig>,
    clients: HashMap<ClientID, UserPermissions>,
}

struct UserPermissions {
    r#pub: Vec<TopicPath>,
    sub: Vec<TopicPath>,
}

impl UserPermissions {
    fn read_filter_claim(filter: Option<Vec<String>>) -> Result<Vec<TopicPath>, String> {
        if let Some(filter) = filter {
            filter
                .iter()
                .map(|filter| {
                    topic_utils::parse_topic_path(filter, false).map_err(|err| format!("{:?}", err))
                })
                .collect()
        } else {
            Ok(Vec::new())
        }
    }

    fn from_claims(claims: Claims) -> Result<UserPermissions, String> {
        Ok(UserPermissions {
            r#pub: UserPermissions::read_filter_claim(claims.publ)?,
            sub: UserPermissions::read_filter_claim(claims.subs)?,
        })
    }

    fn may_subscribe(&self, topic: &str) -> bool {
        if let Ok(topic) = topic_utils::parse_topic_path(topic, false) {
            self.sub
                .iter()
                .any(|filter| topic_utils::match_topic_to_topic_filter(filter, &topic))
        } else {
            false
        }
    }

    fn may_publish(&self, topic: &str) -> bool {
        if let Ok(topic) = topic_utils::parse_topic_path(topic, true) {
            self.r#pub
                .iter()
                .any(|filter| topic_utils::match_topic_to_topic_filter(filter, &topic))
        } else {
            false
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: Option<String>,
    publ: Option<Vec<String>>,
    subs: Option<Vec<String>>,
}

impl MosquittoJWTAuthPluginInstance {
    pub(crate) fn new() -> MosquittoJWTAuthPluginInstance {
        MosquittoJWTAuthPluginInstance {
            config: None,
            clients: HashMap::new(),
        }
    }

    pub(crate) fn setup(&mut self, opts: HashMap<&str, &str>) -> Result<(), ()> {
        match MosquittoJWTAuthPluginConfig::from_opts(opts) {
            Ok(config) => {
                self.config = Some(config);
                Ok(())
            }
            Err(err) => {
                eprintln!("jwt-auth: {}", err);
                Err(())
            }
        }
    }

    pub(crate) fn authenticate_user(
        &mut self,
        client_id: ClientID,
        username: &str,
        password: &str,
    ) -> Result<(), ()> {
        let config = self.config.as_ref().unwrap();

        let claims =
            jsonwebtoken::decode::<Claims>(password, config.secret.as_ref(), &config.validation);

        let permissions = claims
            .map_err(|err| format!("{:?}", err))
            .map(|token_data| token_data.claims)
            .and_then(|claims| {
                if claims.sub.is_none() && !config.validate_sub_match_username {
                    Ok(claims)
                } else if let Some(ref sub) = claims.sub {
                    if sub.as_str() == username {
                        Ok(claims)
                    } else {
                        Err(format!(
                            "claim 'sub': '{}' doesn't match username: '{}'",
                            sub, username
                        ))
                    }
                } else {
                    Err("claim 'sub' is missing".to_string())
                }
            })
            .and_then(UserPermissions::from_claims);

        match permissions {
            Ok(permissions) => {
                self.clients.insert(client_id, permissions);
                Ok(())
            }
            Err(err) => {
                eprintln!("jwt-auth: {}", err);
                Err(())
            }
        }
    }

    pub(crate) fn acl_check(
        &self,
        client_id: ClientID,
        acl_type: AclType,
        topic: &str,
    ) -> Result<(), ()> {
        let user_permissions = self.clients.get(&client_id).ok_or(())?;

        let action_allowed = match acl_type {
            AclType::Publish => user_permissions.may_publish(topic),
            AclType::Subscribe => user_permissions.may_subscribe(topic),
        };

        if action_allowed {
            Ok(())
        } else {
            Err(())
        }
    }
}
