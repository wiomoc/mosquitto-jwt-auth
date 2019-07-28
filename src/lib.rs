extern crate base64;
extern crate jsonwebtoken;
#[macro_use]
extern crate serde_derive;

use crate::mosquitto_sys::{AclType, ClientID};
use crate::topic_utils::TopicPath;
use jsonwebtoken::{Algorithm, Validation};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;

pub mod mosquitto_sys;
mod topic_utils;

#[derive(PartialEq, Debug)]
struct MosquittoJWTAuthPluginConfig {
    secret: Vec<u8>,
    validation: Validation,
    validate_sub_match_username: bool,
}

impl MosquittoJWTAuthPluginConfig {
    fn from_opts(opts: HashMap<&str, &str>) -> Result<MosquittoJWTAuthPluginConfig, &'static str> {
        let alg = Algorithm::from_str(opts.get("jwt_alg").ok_or("'auth_opt_jwt_alg' is missing")?)
            .map_err(|_| "'auth_opt_jwt_alg' is not a valid jwt alg")?;

        let secret = if let Some(secret_file_opt) = opts.get("jwt_sec_file") {
            let mut file_contents = Vec::new();

            File::open(secret_file_opt)
                .map_err(|_| "couldn't open secret file")?
                .read_to_end(&mut file_contents)
                .map_err(|_| "couldn't read secret file")?;

            file_contents
        } else if let Some(secret_env_opt) = opts.get("jwt_sec_env") {
            if let Ok(secret_base64) = env::var(secret_env_opt) {
                base64::decode(&secret_base64).map_err(|_| "invalid base64")?
            } else {
                return Err("environment variable not set");
            }
        } else if let Some(secret_opt) = opts.get("jwt_sec_base64") {
            base64::decode(secret_opt).map_err(|_| "invalid base64")?
        } else {
            return Err("jwt_sec_file, jwt_sec_env or jwt_sec_base64 missing");
        };

        let validate_exp = if let Some(opt) = opts.get("jwt_validate_exp") {
            opt.parse::<bool>()
                .map_err(|_| "'auth_opt_jwt_validate_exp' is not a boolean")?
        } else {
            true
        };

        let validate_sub_match_username =
            if let Some(opt) = opts.get("jwt_validate_sub_match_username") {
                opt.parse::<bool>()
                    .map_err(|_| "'auth_opt_jwt_validate_sub_match_username' is not a boolean")?
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
    client_permissions: HashMap<ClientID, Permissions>,
}

#[derive(PartialEq, Debug)]
struct Permissions {
    r#pub: Vec<TopicPath>,
    sub: Vec<TopicPath>,
}

impl Permissions {
    fn read_filter_claim(filter: Option<Vec<String>>) -> Result<Vec<TopicPath>, String> {
        if let Some(filter) = filter {
            filter
                .iter()
                .map(|filter| {
                    topic_utils::parse_topic_path(filter, true).map_err(|err| format!("{:?}", err))
                })
                .collect()
        } else {
            Ok(Vec::new())
        }
    }

    fn from_claims(claims: Claims) -> Result<Permissions, String> {
        Ok(Permissions {
            r#pub: Permissions::read_filter_claim(claims.publ)?,
            sub: Permissions::read_filter_claim(claims.subs)?,
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
            client_permissions: HashMap::new(),
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
                if !config.validate_sub_match_username {
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
            .and_then(Permissions::from_claims);

        match permissions {
            Ok(permissions) => {
                self.client_permissions.insert(client_id, permissions);
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
        let permissions = self.client_permissions.get(&client_id).ok_or(())?;

        let action_allowed = match acl_type {
            AclType::Publish => permissions.may_publish(topic),
            AclType::Subscribe => permissions.may_subscribe(topic),
        };

        if action_allowed {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_opts_empty_opts() {
        let opts = HashMap::new();

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);

        assert_eq!(result.err().unwrap(), "'auth_opt_jwt_alg' is missing");
    }

    #[test]
    fn test_config_from_opts_unknown_algorithm() {
        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "HS344");

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);

        assert_eq!(
            result.err().unwrap(),
            "'auth_opt_jwt_alg' is not a valid jwt alg"
        );
    }

    #[test]
    fn test_config_from_opts_sec_missing() {
        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "HS256");

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);

        assert_eq!(
            result.err().unwrap(),
            "jwt_sec_file, jwt_sec_env or jwt_sec_base64 missing"
        );
    }

    #[test]
    fn test_config_from_opts_sec_file_valid() {
        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_file", "tests/public.der");

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);

        assert!(result.ok().unwrap().secret.starts_with(b"\x30\x82\x01\x22\x30\x0d\x06\x09"));
    }


    #[test]
    fn test_config_from_opts_sec_file_not_found() {
        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_file", "tests/publicsfd.der");

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);

        assert_eq!(result.err().unwrap(), "couldn't open secret file");
    }

    #[test]
    fn test_config_from_opts_sec_env_invalid_base64() {
        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "HS256");
        opts.insert("jwt_sec_env", "jwt_sec_env");

        env::set_var("jwt_sec_env", "))");

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);
        env::remove_var("jwt_sec_env");

        assert_eq!(result.err().unwrap(), "invalid base64");
    }

    #[test]
    fn test_config_from_opts_env_valid_base64() {
        env::set_var("jwt_sec_env", "AABB");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_env", "jwt_sec_env");

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);

        assert_eq!(
            result.ok().unwrap(),
            MosquittoJWTAuthPluginConfig {
                secret: vec![0, 0, 0x41],
                validate_sub_match_username: true,
                validation: Validation {
                    leeway: 0,
                    validate_exp: true,
                    validate_nbf: false,
                    aud: None,
                    iss: None,
                    sub: None,
                    algorithms: vec![Algorithm::RS256],
                },
            }
        );
    }

    #[test]
    fn test_config_from_opts_sec_env_not_set() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "HS256");
        opts.insert("jwt_sec_env", "jwt_sec_env");

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);

        assert_eq!(result.err().unwrap(), "environment variable not set");
    }

    #[test]
    fn test_config_from_opts_sec_invalid_base64() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "HS256");
        opts.insert("jwt_sec_base64", "AAB(");

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);

        assert_eq!(result.err().unwrap(), "invalid base64");
    }

    #[test]
    fn test_config_from_opts_valid_base64() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_base64", "AABB");

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);

        assert_eq!(
            result.ok().unwrap(),
            MosquittoJWTAuthPluginConfig {
                secret: vec![0, 0, 0x41],
                validate_sub_match_username: true,
                validation: Validation {
                    leeway: 0,
                    validate_exp: true,
                    validate_nbf: false,
                    aud: None,
                    iss: None,
                    sub: None,
                    algorithms: vec![Algorithm::RS256],
                },
            }
        );
    }

    #[test]
    fn test_config_from_opts_validate_exp_false() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_base64", "AABB");
        opts.insert("jwt_validate_exp", "false");

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);

        assert_eq!(
            result.ok().unwrap(),
            MosquittoJWTAuthPluginConfig {
                secret: vec![0, 0, 0x41],
                validate_sub_match_username: true,
                validation: Validation {
                    leeway: 0,
                    validate_exp: false,
                    validate_nbf: false,
                    aud: None,
                    iss: None,
                    sub: None,
                    algorithms: vec![Algorithm::RS256],
                },
            }
        );
    }

    #[test]
    fn test_config_from_opts_validate_exp_not_a_boolean() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_base64", "AABB");
        opts.insert("jwt_validate_exp", "sdfsdf");

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);

        assert_eq!(
            result.err().unwrap(),
            "'auth_opt_jwt_validate_exp' is not a boolean"
        );
    }

    #[test]
    fn test_config_from_opts_validate_sub_match_username_false() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_base64", "AABB");
        opts.insert("jwt_validate_sub_match_username", "false");

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);

        assert_eq!(
            result.ok().unwrap(),
            MosquittoJWTAuthPluginConfig {
                secret: vec![0, 0, 0x41],
                validate_sub_match_username: false,
                validation: Validation {
                    leeway: 0,
                    validate_exp: true,
                    validate_nbf: false,
                    aud: None,
                    iss: None,
                    sub: None,
                    algorithms: vec![Algorithm::RS256],
                },
            }
        );
    }

    #[test]
    fn test_config_from_opts_validate_sub_match_username_not_a_boolean() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_base64", "AABB");
        opts.insert("jwt_validate_sub_match_username", "sdfsdf");

        let result = MosquittoJWTAuthPluginConfig::from_opts(opts);

        assert_eq!(
            result.err().unwrap(),
            "'auth_opt_jwt_validate_sub_match_username' is not a boolean"
        );
    }

    #[test]
    fn test_permissions_from_claims() {
        let claims = Claims {
            sub: None,
            publ: None,
            subs: Some(vec!["#".to_string(), "/123/55".to_string()]),
        };

        let result = Permissions::from_claims(claims);

        assert_eq!(
            result.ok().unwrap(),
            Permissions {
                r#pub: Vec::new(),
                sub: vec![
                    topic_utils::parse_topic_path("#", true).unwrap(),
                    topic_utils::parse_topic_path("/123/55", true).unwrap()
                ],
            }
        )
    }

    #[test]
    fn test_permissions_may_subscribe() {
        let permissions = Permissions {
            r#pub: Vec::new(),
            sub: vec![
                topic_utils::parse_topic_path("/123/55", true).unwrap(),
                topic_utils::parse_topic_path("/+/23", true).unwrap(),
            ],
        };

        let result = permissions.may_subscribe("/123");
        assert_eq!(result, false);

        let result = permissions.may_subscribe("/123/23");
        assert_eq!(result, true);

        let result = permissions.may_subscribe("/12#3/23");
        assert_eq!(result, false)
    }

    #[test]
    fn test_permissions_may_publish() {
        let permissions = Permissions {
            sub: Vec::new(),
            r#pub: vec![
                topic_utils::parse_topic_path("/123/55", true).unwrap(),
                topic_utils::parse_topic_path("/+/23", true).unwrap(),
            ],
        };

        let result = permissions.may_publish("/123");
        assert_eq!(result, false);

        let result = permissions.may_publish("/123/23");
        assert_eq!(result, true);

        let result = permissions.may_publish("/12#3/23");
        assert_eq!(result, false)
    }

    #[test]
    fn test_setup_valid() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_base64", "AABB");

        let mut instance = MosquittoJWTAuthPluginInstance::new();
        let result = instance.setup(opts);

        assert_eq!(result.is_ok(), true);
        assert_eq!(
            instance.config.unwrap(),
            MosquittoJWTAuthPluginConfig {
                secret: vec![0, 0, 0x41],
                validate_sub_match_username: true,
                validation: Validation {
                    leeway: 0,
                    validate_exp: true,
                    validate_nbf: false,
                    aud: None,
                    iss: None,
                    sub: None,
                    algorithms: vec![Algorithm::RS256],
                },
            }
        );
    }

    #[test]
    fn test_setup_invalid() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_base64", "AA((");

        let mut instance = MosquittoJWTAuthPluginInstance::new();
        let result = instance.setup(opts);

        assert_eq!(result.is_ok(), false);
    }

    #[test]
    fn test_authenticate_user_signature_mismatch() {
        let mut instance = MosquittoJWTAuthPluginInstance::new();
        instance.config = Some(MosquittoJWTAuthPluginConfig {
            validation: Validation::default(),
            validate_sub_match_username: true,
            secret: base64::decode("XmThTwNsoLBlbk3cbOi5r2g1EIJNT7o7zSKc9tMUsIg").unwrap(),
        });

        let client_id = 33 as ClientID;

        let result = instance.authenticate_user(client_id, "user", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYW1lIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SLwblB5xA5hytO2CCDI49iI50SuseVYInhdtXMhzN4s");

        assert_eq!(result.is_err(), true);
        assert_eq!(instance.client_permissions.contains_key(&client_id), false);
    }

    #[test]
    fn test_authenticate_user_sub_username_mismatch() {
        let mut instance = MosquittoJWTAuthPluginInstance::new();
        instance.config = Some(MosquittoJWTAuthPluginConfig {
            validation: Validation {
                validate_exp: false,
                ..Validation::default()
            },
            validate_sub_match_username: true,
            secret: base64::decode("XmThTwNsoLBlbk3cbOi5r2g1EIJNT7o7zSKy9tMUsIg").unwrap(),
        });

        let client_id = 33 as ClientID;

        let result = instance.authenticate_user(client_id, "user", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYW1lIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SLwblB5xA5hytO2CCDI49iI50SuseVYInhdtXMhzN4s");

        assert_eq!(result.is_err(), true);
        assert_eq!(instance.client_permissions.contains_key(&client_id), false);
    }

    #[test]
    fn test_authenticate_user_invalid_sub_missing() {
        let mut instance = MosquittoJWTAuthPluginInstance::new();
        instance.config = Some(MosquittoJWTAuthPluginConfig {
            validation: Validation {
                validate_exp: false,
                ..Validation::default()
            },
            validate_sub_match_username: true,
            secret: base64::decode("XmThTwNsoLBlbk3cbOi5r2g1EIJNT7o7zSKy9tMUsIg").unwrap(),
        });

        let client_id = 33 as ClientID;

        let result = instance.authenticate_user(client_id, "user", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.aelYzUN2movT8bG3flOX3aNWZ8kS2ijQPVUUbhA7TW0");

        assert_eq!(result.is_err(), true);
        assert_eq!(instance.client_permissions.contains_key(&client_id), false);
    }

    #[test]
    fn test_authenticate_user_sub_valid_missing() {
        let mut instance = MosquittoJWTAuthPluginInstance::new();
        instance.config = Some(MosquittoJWTAuthPluginConfig {
            validation: Validation {
                validate_exp: false,
                ..Validation::default()
            },
            validate_sub_match_username: false,
            secret: base64::decode("XmThTwNsoLBlbk3cbOi5r2g1EIJNT7o7zSKy9tMUsIg").unwrap(),
        });

        let client_id = 33 as ClientID;

        let result = instance.authenticate_user(client_id, "user", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.aelYzUN2movT8bG3flOX3aNWZ8kS2ijQPVUUbhA7TW0");

        assert_eq!(result.is_ok(), true);
        assert_eq!(
            instance.client_permissions.get(&client_id).unwrap(),
            &Permissions {
                sub: Vec::new(),
                r#pub: Vec::new(),
            }
        );
    }

    #[test]
    fn test_authenticate_user_sub_matching() {
        let mut instance = MosquittoJWTAuthPluginInstance::new();
        instance.config = Some(MosquittoJWTAuthPluginConfig {
            validation: Validation {
                validate_exp: false,
                ..Validation::default()
            },
            validate_sub_match_username: true,
            secret: base64::decode("XmThTwNsoLBlbk3cbOi5r2g1EIJNT7o7zSKy9tMUsIg").unwrap(),
        });

        let client_id = 33 as ClientID;

        let result = instance.authenticate_user(client_id, "name", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYW1lIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SLwblB5xA5hytO2CCDI49iI50SuseVYInhdtXMhzN4s");

        assert_eq!(result.is_ok(), true);
        assert_eq!(
            instance.client_permissions.get(&client_id).unwrap(),
            &Permissions {
                sub: Vec::new(),
                r#pub: Vec::new(),
            }
        );
    }

    #[test]
    fn test_acl_check() {
        let mut instance = MosquittoJWTAuthPluginInstance::new();
        instance.config = Some(MosquittoJWTAuthPluginConfig {
            validation: Validation::default(),
            validate_sub_match_username: true,
            secret: Vec::new(),
        });

        let client_id0 = 33 as ClientID;
        let client_id1 = 36 as ClientID;

        instance.client_permissions.insert(
            client_id0,
            Permissions {
                sub: Vec::new(),
                r#pub: vec![
                    topic_utils::parse_topic_path("/123/55", true).unwrap(),
                    topic_utils::parse_topic_path("/+/23", true).unwrap(),
                ],
            },
        );

        instance.client_permissions.insert(
            client_id1,
            Permissions {
                r#pub: Vec::new(),
                sub: vec![
                    topic_utils::parse_topic_path("/123/55", true).unwrap(),
                    topic_utils::parse_topic_path("/+/23", true).unwrap(),
                ],
            },
        );

        let result = instance.acl_check(client_id0, AclType::Publish, "/11");
        assert_eq!(result, Err(()));

        let result = instance.acl_check(client_id0, AclType::Publish, "/123/55");
        assert_eq!(result, Ok(()));

        let result = instance.acl_check(client_id0, AclType::Subscribe, "/123/55");
        assert_eq!(result, Err(()));

        let result = instance.acl_check(client_id1, AclType::Subscribe, "/11");
        assert_eq!(result, Err(()));

        let result = instance.acl_check(client_id1, AclType::Subscribe, "/123/55");
        assert_eq!(result, Ok(()));

        let result = instance.acl_check(client_id1, AclType::Publish, "/123/55");
        assert_eq!(result, Err(()));

        let result = instance.acl_check(0 as ClientID, AclType::Publish, "/123/55");
        assert_eq!(result, Err(()));
    }
}
