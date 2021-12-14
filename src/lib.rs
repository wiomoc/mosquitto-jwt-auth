extern crate base64;
extern crate biscuit;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use crate::mosquitto_sys::{AclType, ClientID};
use crate::topic_utils::TopicPath;
use biscuit::jwa::SignatureAlgorithm;
use biscuit::jwk::JWKSet;
use biscuit::jws::Secret;
use biscuit::{Validation, ValidationOptions, JWT};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;

pub mod mosquitto_sys;
mod topic_utils;

enum SignatureVerifier {
    Key {
        secret: Secret,
        signature_algorithm: SignatureAlgorithm,
    },
    JWKS(JWKSet<biscuit::Empty>),
}

struct PluginConfig {
    verifier: SignatureVerifier,
    validation: ValidationOptions,
    validate_sub_match_username: bool,
}

impl PluginConfig {
    fn parse_signature_algorithm(string: &str) -> Result<SignatureAlgorithm, ()> {
        Ok(match string {
            "HS256" => SignatureAlgorithm::HS256,
            "HS384" => SignatureAlgorithm::HS384,
            "HS512" => SignatureAlgorithm::HS512,
            "ES256" => SignatureAlgorithm::ES256,
            "ES384" => SignatureAlgorithm::ES384,
            "ES512" => SignatureAlgorithm::ES512,
            "RS256" => SignatureAlgorithm::RS256,
            "RS384" => SignatureAlgorithm::RS384,
            "RS512" => SignatureAlgorithm::RS512,
            "PS256" => SignatureAlgorithm::PS256,
            "PS384" => SignatureAlgorithm::PS384,
            "PS512" => SignatureAlgorithm::PS512,
            _ => return Err(()),
        })
    }
    fn from_opts(opts: HashMap<&str, &str>) -> Result<PluginConfig, &'static str> {
        let verifier = if let Some(jwks_file) = opts.get("jwt_jwks_file") {
            let mut file_contents = Vec::new();
            File::open(jwks_file)
                .map_err(|_| "couldn't open jwks file")?
                .read_to_end(&mut file_contents)
                .map_err(|_| "couldn't read jwks file")?;
            SignatureVerifier::JWKS(
                serde_json::from_str(String::from_utf8_lossy(&file_contents).as_ref())
                    .map_err(|_| "couldn't parse jwks file")?,
            )
        } else {
            let signature_algorithm = PluginConfig::parse_signature_algorithm(
                &opts.get("jwt_alg").ok_or("'auth_opt_jwt_alg' is missing")?[..],
            )
            .map_err(|_| "'auth_opt_jwt_alg' is not a valid jwt alg")?;

            let secret_bytes = if let Some(secret_file_opt) = opts.get("jwt_sec_file") {
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

            let secret = match signature_algorithm {
                SignatureAlgorithm::HS256
                | SignatureAlgorithm::HS384
                | SignatureAlgorithm::HS512 => Secret::Bytes(secret_bytes),
                _ => Secret::PublicKey(secret_bytes),
            };

            SignatureVerifier::Key {
                secret,
                signature_algorithm,
            }
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

        let validation = ValidationOptions {
            expiry: if validate_exp {
                Validation::Validate(())
            } else {
                Validation::Ignored
            },
            ..Default::default()
        };

        Ok(PluginConfig {
            verifier,
            validation,
            validate_sub_match_username,
        })
    }
}

pub(crate) struct PluginInstance {
    config: Option<PluginConfig>,
    client_permissions: HashMap<ClientID, Permissions>,
}

#[derive(PartialEq, Debug)]
struct Permissions {
    r#pub: Vec<TopicPath>,
    sub: Vec<TopicPath>,
}

impl Permissions {
    fn read_filter_claim(filter: Option<&[String]>) -> Result<Vec<TopicPath>, String> {
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

    fn from_claims(claims: &Claims) -> Result<Permissions, String> {
        Ok(Permissions {
            r#pub: Permissions::read_filter_claim(claims.publ.as_deref())?,
            sub: Permissions::read_filter_claim(claims.subs.as_deref())?,
        })
    }

    fn may_subscribe(&self, topic: &str) -> bool {
        if let Ok(topic) = topic_utils::parse_topic_path(topic, true) {
            self.sub
                .iter()
                .any(|filter| topic_utils::match_topic_to_topic_filter(filter, &topic))
        } else {
            false
        }
    }

    fn may_publish(&self, topic: &str) -> bool {
        if let Ok(topic) = topic_utils::parse_topic_path(topic, false) {
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

impl PluginInstance {
    pub(crate) fn new() -> PluginInstance {
        PluginInstance {
            config: None,
            client_permissions: HashMap::new(),
        }
    }

    pub(crate) fn setup(&mut self, opts: HashMap<&str, &str>) -> Result<(), ()> {
        match PluginConfig::from_opts(opts) {
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

    fn extract_jwt(
        token: Option<&str>,
        config: &PluginConfig,
        username: Option<&str>,
    ) -> Result<Permissions, String> {
        let token = token.ok_or_else(|| "token not given".to_string())?;
        let token = JWT::<Claims, biscuit::Empty>::new_encoded(token);
        let token = match &config.verifier {
            SignatureVerifier::Key {
                signature_algorithm,
                secret,
            } => token.decode(secret, signature_algorithm.clone()),
            SignatureVerifier::JWKS(jwks) => token.decode_with_jwks(&jwks, None),
        }
        .map_err(|err| format!("error decoding jwt: {:?}", err))?;
        token
            .validate(config.validation.clone())
            .map_err(|err| format!("error validating jwt: {:?}", err))?;
        let claims = &token
            .payload()
            .map_err(|err| format!("error decoding jwt claims: {:?}", err))?;
        if config.validate_sub_match_username {
            if let Some(ref sub) = claims.registered.subject {
                if let Some(username) = username {
                    if username != sub {
                        return Err(format!(
                            "claim 'sub': '{}' doesn't match username: '{}'",
                            sub, username
                        ));
                    }
                } else {
                    return Err("username not set".to_string());
                }
            } else {
                return Err("claim 'sub' is missing".to_string());
            }
        }
        Permissions::from_claims(&claims.private)
    }

    pub(crate) fn authenticate_user(
        &mut self,
        client_id: ClientID,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<(), ()> {
        let config = self.config.as_ref().unwrap();
        let permissions = PluginInstance::extract_jwt(password, config, username);
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
    use crate::SignatureVerifier;
    use biscuit::jwa::{Algorithm, SignatureAlgorithm};
    use biscuit::jwk::{AlgorithmParameters, CommonParameters, RSAKeyParameters, RSAKeyType, JWK};
    use num_bigint::BigUint;

    #[test]
    fn test_config_from_opts_empty_opts() {
        let opts = HashMap::new();

        let result = PluginConfig::from_opts(opts);

        assert_eq!(result.err().unwrap(), "'auth_opt_jwt_alg' is missing");
    }

    #[test]
    fn test_config_from_opts_unknown_algorithm() {
        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "HS344");

        let result = PluginConfig::from_opts(opts);

        assert_eq!(
            result.err().unwrap(),
            "'auth_opt_jwt_alg' is not a valid jwt alg"
        );
    }

    #[test]
    fn test_config_from_opts_sec_missing() {
        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "HS256");

        let result = PluginConfig::from_opts(opts);

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

        let result = PluginConfig::from_opts(opts);

        if let SignatureVerifier::Key { secret, .. } = result.unwrap().verifier {
            if let Secret::PublicKey(secret) = secret {
                assert!(secret.starts_with(b"\x30\x82\x01\x22\x30\x0d\x06\x09"));
            } else {
                panic!()
            }
        } else {
            panic!()
        }
    }

    #[test]
    fn test_config_from_opts_sec_file_not_found() {
        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_file", "tests/publicsfd.der");

        let result = PluginConfig::from_opts(opts);

        assert_eq!(result.err().unwrap(), "couldn't open secret file");
    }

    #[test]
    fn test_config_from_opts_sec_env_invalid_base64() {
        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "HS256");
        opts.insert("jwt_sec_env", "jwt_sec_env");

        env::set_var("jwt_sec_env", "))");

        let result = PluginConfig::from_opts(opts);
        env::remove_var("jwt_sec_env");

        assert_eq!(result.err().unwrap(), "invalid base64");
    }

    fn assert_same_config(actual: PluginConfig, expected: PluginConfig) {
        assert_eq!(
            actual.validate_sub_match_username,
            expected.validate_sub_match_username
        );
        assert!(actual.validation == expected.validation);

        match (actual.verifier, expected.verifier) {
            (
                SignatureVerifier::Key {
                    secret: secret_a,
                    signature_algorithm: signature_algorithm_a,
                },
                SignatureVerifier::Key {
                    secret: secret_b,
                    signature_algorithm: signature_algorithm_b,
                },
            ) => {
                match (secret_a, secret_b) {
                    (Secret::Bytes(a), Secret::Bytes(b)) => assert_eq!(a, b),
                    (Secret::PublicKey(a), Secret::PublicKey(b)) => assert_eq!(a, b),
                    _ => panic!(),
                };
                assert_eq!(signature_algorithm_a, signature_algorithm_b);
            }
            (SignatureVerifier::JWKS(a), SignatureVerifier::JWKS(b)) => assert!(a == b),
            _ => panic!(),
        }
    }

    #[test]
    fn test_config_from_opts_env_valid_base64() {
        env::set_var("jwt_sec_env", "AABB");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "HS256");
        opts.insert("jwt_sec_env", "jwt_sec_env");

        let result = PluginConfig::from_opts(opts);

        assert_same_config(
            result.ok().unwrap(),
            PluginConfig {
                verifier: SignatureVerifier::Key {
                    secret: Secret::Bytes(vec![0, 0, 0x41]),
                    signature_algorithm: SignatureAlgorithm::HS256,
                },
                validate_sub_match_username: true,
                validation: ValidationOptions {
                    expiry: Validation::Validate(()),
                    ..Default::default()
                },
            },
        );
    }

    #[test]
    fn test_config_from_opts_valid_jwks() {
        let mut opts = HashMap::new();
        opts.insert("jwt_jwks_file", "tests/jwks.json");

        let result = PluginConfig::from_opts(opts);

        assert_same_config(
            result.ok().unwrap(),
            PluginConfig {
                verifier: SignatureVerifier::JWKS(JWKSet{keys: vec![JWK{
                    additional: biscuit::Empty{},
                    common: CommonParameters {
                        algorithm: Some(Algorithm::Signature(SignatureAlgorithm::RS256)),
                        key_id: Some("test1".to_string()),
                        ..Default::default()
                    },
                    algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                        key_type: RSAKeyType::RSA,
                        e: BigUint::from_bytes_be(&base64::decode("AQAB").unwrap()),
                        n: BigUint::from_bytes_be(&base64::decode("ghhGwdfUlPnbqbIGKRkp3ATiBP96iYf3g687/dv82XC1SAp+JQxnPLSVz83s9iiBWLV/3IA08ot/GuZTBLYhIW/EX5OT0KOP1GhnSlXyo90dMq+yMQl+kHRP2A38gjFhG2QFf4UMjSHcEV4gJ+htfX6Tm/E5Ow4HJXx8nYiNAdLFGdUl1j44lJDwCa8H+Bz2A54HZ5wXQ7mYmNImueX/raGK6KWOzLWQeNp2NDa9nXHTU0cZ8Qe1R51EYzs5sXY8w/Nu8aYW9bDe6xI1Gelf3CeIQFioW3ttqtv49Fv5Kfbf6J6Ce36MZyZOFMI2pikNEMAq1npphC5XIdd55QtsWQ").unwrap()),
                            ..Default::default()
                    })
                }]}),
                validate_sub_match_username: true,
                validation: ValidationOptions {
                    expiry: Validation::Validate(()),
                    ..Default::default()
                },
            },
        );
    }

    #[test]
    fn test_config_from_opts_sec_env_not_set() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "HS256");
        opts.insert("jwt_sec_env", "jwt_sec_env");

        let result = PluginConfig::from_opts(opts);

        assert_eq!(result.err().unwrap(), "environment variable not set");
    }

    #[test]
    fn test_config_from_opts_sec_invalid_base64() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "HS256");
        opts.insert("jwt_sec_base64", "AAB(");

        let result = PluginConfig::from_opts(opts);

        assert_eq!(result.err().unwrap(), "invalid base64");
    }

    #[test]
    fn test_config_from_opts_valid_base64() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_base64", "AABB");

        let result = PluginConfig::from_opts(opts);

        assert_same_config(
            result.ok().unwrap(),
            PluginConfig {
                verifier: SignatureVerifier::Key {
                    secret: Secret::PublicKey(vec![0, 0, 0x41]),
                    signature_algorithm: SignatureAlgorithm::RS256,
                },
                validate_sub_match_username: true,
                validation: ValidationOptions {
                    expiry: Validation::Validate(()),
                    ..Default::default()
                },
            },
        );
    }

    #[test]
    fn test_config_from_opts_validate_exp_false() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_base64", "AABB");
        opts.insert("jwt_validate_exp", "false");

        let result = PluginConfig::from_opts(opts);

        assert_same_config(
            result.ok().unwrap(),
            PluginConfig {
                verifier: SignatureVerifier::Key {
                    secret: Secret::PublicKey(vec![0, 0, 0x41]),
                    signature_algorithm: SignatureAlgorithm::RS256,
                },
                validate_sub_match_username: true,
                validation: ValidationOptions {
                    expiry: Validation::Ignored,
                    ..Default::default()
                },
            },
        );
    }

    #[test]
    fn test_config_from_opts_validate_exp_not_a_boolean() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_base64", "AABB");
        opts.insert("jwt_validate_exp", "sdfsdf");

        let result = PluginConfig::from_opts(opts);

        assert_eq!(
            result.err().unwrap(),
            "'auth_opt_jwt_validate_exp' is not a boolean"
        );
    }

    #[test]
    fn test_config_from_opts_validate_sub_match_username_false() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "HS256");
        opts.insert("jwt_sec_base64", "AABB");
        opts.insert("jwt_validate_sub_match_username", "false");

        let result = PluginConfig::from_opts(opts);

        assert_same_config(
            result.ok().unwrap(),
            PluginConfig {
                verifier: SignatureVerifier::Key {
                    secret: Secret::Bytes(vec![0, 0, 0x41]),
                    signature_algorithm: SignatureAlgorithm::HS256,
                },
                validate_sub_match_username: false,
                validation: ValidationOptions {
                    expiry: Validation::Validate(()),
                    ..Default::default()
                },
            },
        );
    }

    #[test]
    fn test_config_from_opts_validate_sub_match_username_not_a_boolean() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_base64", "AABB");
        opts.insert("jwt_validate_sub_match_username", "sdfsdf");

        let result = PluginConfig::from_opts(opts);

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

        let result = Permissions::from_claims(&claims);

        assert_eq!(
            result.ok().unwrap(),
            Permissions {
                r#pub: Vec::new(),
                sub: vec![
                    topic_utils::parse_topic_path("#", true).unwrap(),
                    topic_utils::parse_topic_path("/123/55", true).unwrap(),
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
                topic_utils::parse_topic_path("/abc/#", true).unwrap(),
            ],
        };

        let result = permissions.may_subscribe("/123");
        assert_eq!(result, false);

        let result = permissions.may_subscribe("/123/23");
        assert_eq!(result, true);

        let result = permissions.may_subscribe("/+/23");
        assert_eq!(result, true);

        let result = permissions.may_subscribe("/12#3/23");
        assert_eq!(result, false);

        let result = permissions.may_subscribe("/abc/23");
        assert_eq!(result, true);

        let result = permissions.may_subscribe("/abc/#");
        assert_eq!(result, true);
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

        let result = permissions.may_publish("/123/55");
        assert_eq!(result, true);

        let result = permissions.may_publish("/123/55/33");
        assert_eq!(result, false);

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

        let mut instance = PluginInstance::new();
        let result = instance.setup(opts);

        assert_eq!(result.is_ok(), true);
        assert_same_config(
            instance.config.unwrap(),
            PluginConfig {
                verifier: SignatureVerifier::Key {
                    secret: Secret::PublicKey(vec![0, 0, 0x41]),
                    signature_algorithm: SignatureAlgorithm::RS256,
                },
                validate_sub_match_username: true,
                validation: ValidationOptions {
                    expiry: Validation::Validate(()),
                    ..Default::default()
                },
            },
        );
    }

    #[test]
    fn test_setup_invalid() {
        env::remove_var("jwt_sec_env");

        let mut opts = HashMap::new();
        opts.insert("jwt_alg", "RS256");
        opts.insert("jwt_sec_base64", "AA((");

        let mut instance = PluginInstance::new();
        let result = instance.setup(opts);

        assert_eq!(result.is_ok(), false);
    }

    #[test]
    fn test_authenticate_user_signature_mismatch() {
        let mut instance = PluginInstance::new();
        instance.config = Some(PluginConfig {
            validation: ValidationOptions::default(),
            validate_sub_match_username: true,
            verifier: SignatureVerifier::Key {
                signature_algorithm: SignatureAlgorithm::HS256,
                secret: Secret::Bytes(
                    base64::decode("XmThTwNsoLBlbk3cbOi5r2g1EIJNT7o7zSKc9tMUsIg").unwrap(),
                ),
            },
        });

        let client_id = 33 as ClientID;

        let result = instance.authenticate_user(client_id, Some("user"), Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYW1lIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SLwblB5xA5hytO2CCDI49iI50SuseVYInhdtXMhzN4s"));

        assert_eq!(result.is_err(), true);
        assert_eq!(instance.client_permissions.contains_key(&client_id), false);
    }

    #[test]
    fn test_authenticate_user_sub_username_mismatch() {
        let mut instance = PluginInstance::new();
        instance.config = Some(PluginConfig {
            validation: ValidationOptions {
                expiry: Validation::Ignored,
                ..Default::default()
            },
            validate_sub_match_username: true,
            verifier: SignatureVerifier::Key {
                signature_algorithm: SignatureAlgorithm::HS256,
                secret: Secret::Bytes(
                    base64::decode("XmThTwNsoLBlbk3cbOi5r2g1EIJNT7o7zSKy9tMUsIg").unwrap(),
                ),
            },
        });

        let client_id = 33 as ClientID;

        let result = instance.authenticate_user(client_id, Some("user"), Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYW1lIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SLwblB5xA5hytO2CCDI49iI50SuseVYInhdtXMhzN4s"));

        assert_eq!(result.is_err(), true);
        assert_eq!(instance.client_permissions.contains_key(&client_id), false);
    }

    #[test]
    fn test_authenticate_user_username_not_set() {
        let mut instance = PluginInstance::new();
        instance.config = Some(PluginConfig {
            validation: ValidationOptions {
                expiry: Validation::Ignored,
                ..Default::default()
            },
            validate_sub_match_username: true,
            verifier: SignatureVerifier::Key {
                signature_algorithm: SignatureAlgorithm::HS256,
                secret: Secret::Bytes(
                    base64::decode("XmThTwNsoLBlbk3cbOi5r2g1EIJNT7o7zSKy9tMUsIg").unwrap(),
                ),
            },
        });

        let client_id = 33 as ClientID;

        let result = instance.authenticate_user(client_id, None, Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYW1lIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SLwblB5xA5hytO2CCDI49iI50SuseVYInhdtXMhzN4s"));

        assert_eq!(result.is_err(), true);
        assert_eq!(instance.client_permissions.contains_key(&client_id), false);
    }

    #[test]
    fn test_authenticate_user_password_not_set() {
        let mut instance = PluginInstance::new();
        instance.config = Some(PluginConfig {
            validation: ValidationOptions {
                expiry: Validation::Ignored,
                ..Default::default()
            },
            validate_sub_match_username: true,
            verifier: SignatureVerifier::Key {
                signature_algorithm: SignatureAlgorithm::HS256,
                secret: Secret::Bytes(
                    base64::decode("XmThTwNsoLBlbk3cbOi5r2g1EIJNT7o7zSKy9tMUsIg").unwrap(),
                ),
            },
        });

        let client_id = 33 as ClientID;

        let result = instance.authenticate_user(client_id, Some("user"), None);

        assert_eq!(result.is_err(), true);
        assert_eq!(instance.client_permissions.contains_key(&client_id), false);
    }

    #[test]
    fn test_authenticate_user_invalid_sub_missing() {
        let mut instance = PluginInstance::new();
        instance.config = Some(PluginConfig {
            validation: ValidationOptions {
                expiry: Validation::Ignored,
                ..Default::default()
            },
            validate_sub_match_username: true,
            verifier: SignatureVerifier::Key {
                signature_algorithm: SignatureAlgorithm::HS256,
                secret: Secret::Bytes(
                    base64::decode("XmThTwNsoLBlbk3cbOi5r2g1EIJNT7o7zSKy9tMUsIg").unwrap(),
                ),
            },
        });

        let client_id = 33 as ClientID;

        let result = instance.authenticate_user(client_id, Some("user"), Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.aelYzUN2movT8bG3flOX3aNWZ8kS2ijQPVUUbhA7TW0"));

        assert_eq!(result.is_err(), true);
        assert_eq!(instance.client_permissions.contains_key(&client_id), false);
    }

    #[test]
    fn test_authenticate_user_sub_valid_missing() {
        let mut instance = PluginInstance::new();
        instance.config = Some(PluginConfig {
            validation: ValidationOptions {
                expiry: Validation::Ignored,
                ..Default::default()
            },
            validate_sub_match_username: false,
            verifier: SignatureVerifier::Key {
                signature_algorithm: SignatureAlgorithm::HS256,
                secret: Secret::Bytes(
                    base64::decode("XmThTwNsoLBlbk3cbOi5r2g1EIJNT7o7zSKy9tMUsIg").unwrap(),
                ),
            },
        });

        let client_id = 33 as ClientID;

        let result = instance.authenticate_user(client_id, Some("user"), Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.aelYzUN2movT8bG3flOX3aNWZ8kS2ijQPVUUbhA7TW0"));

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
        let mut instance = PluginInstance::new();
        instance.config = Some(PluginConfig {
            validation: ValidationOptions {
                expiry: Validation::Ignored,
                ..Default::default()
            },
            validate_sub_match_username: true,
            verifier: SignatureVerifier::Key {
                signature_algorithm: SignatureAlgorithm::HS256,
                secret: Secret::Bytes(
                    base64::decode("XmThTwNsoLBlbk3cbOi5r2g1EIJNT7o7zSKy9tMUsIg").unwrap(),
                ),
            },
        });

        let client_id = 33 as ClientID;

        let result = instance.authenticate_user(client_id, Some("name"), Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYW1lIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SLwblB5xA5hytO2CCDI49iI50SuseVYInhdtXMhzN4s"));

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
    fn test_authenticate_user_sub_matching_jwks() {
        let mut instance = PluginInstance::new();
        let mut opts = HashMap::new();
        opts.insert("jwt_jwks_file", "tests/jwks.json");

        let result = PluginConfig::from_opts(opts);
        instance.config = Some(result.unwrap());

        let client_id = 33 as ClientID;

        let result = instance.authenticate_user(client_id, Some("name"), Some("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QxIn0.eyJzdWIiOiJuYW1lIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.dHa1960ZrCnTiDGYuyLGZZuRmaZICUyJDnj2ILL7C-5EpsCByyIByhttvqN4gjVpT7HhitoBFd-r7ssg0mgv6d6QQd7WX0VCIeD1hFEEr3Q76yzXEmAim5fqYP2lg6vWMQEhewN3xSI8H5TeRksSXu0RknW0s-WkoKaU3JuTh2HsMXdVW-L0yIsM9LOJaJ2UBC3DN0TieRydsjSDmXppblKVgSd4s0nkWFDzvFQmzFKoWxZmx19KXxo9XDzJ3zUOxGp_hH0OTqgMl8XuSETp3TxuezBi3d1HLMSItH3yyvxmN0E_sDQ25v_iAl7C8e7iQZa4JdwA-QCy85JfabBwFQ"));

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
        let mut instance = PluginInstance::new();
        instance.config = Some(PluginConfig {
            validation: Default::default(),
            validate_sub_match_username: true,
            verifier: SignatureVerifier::Key {
                signature_algorithm: SignatureAlgorithm::HS256,
                secret: Secret::Bytes(vec![]),
            },
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
