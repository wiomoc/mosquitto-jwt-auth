# mosquitto-jwt-auth

![Build](https://github.com/wiomoc/mosquitto-jwt-auth/actions/workflows/build.yml/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/wiomoc/mosquitto-jwt-auth/badge.svg)](https://coveralls.io/github/wiomoc/mosquitto-jwt-auth)

Simple Plugin for Mosquitto which enables authentication and authorisation via JWT as MQTT password.

Requires at least Mosquitto v1.6.3

## Building
**Prebuild** version is available [here](https://github.com/wiomoc/mosquitto-jwt-auth/releases/latest)

1. If not done yet, [install Rust](https://www.rust-lang.org/tools/install)
2. Clone `git clone git@github.com:wiomoc/mosquitto-jwt-auth.git`
3. Build `cargo build --release`, on success plugin should be located at `target/release/libmosquitto_jwt_auth.so`

## Configuration
`auth_plugin` should point to the path of `libmosquitto_jwt_auth.so`

| Property           | Valid values | Usage |
|--------------------|------|-------|
| `auth_opt_jwt_alg` | `HS256`, `HS384`, `HS512`, `ES256`, `ES384`, `RS256`, `RS384`, `RS512`| Sets the algorithm of the JWT signature |
| `auth_opt_jwt_sec_file` | `<path to file>` | Path to the file which contains the secret used for verification of the signature. Should be DER-encoded for RSA |
| `auth_opt_jwt_sec_env` | `<enviroment variable name>` | Name of the environment variable which contains the base64 encoded secret used for verification of the signature. |
| `auth_opt_jwt_sec_base64` | `<base64-encoded-secret>` | Base64 encoded secret used for verification of the signature. |
| `auth_opt_jwt_validate_exp` | _(default)_ `true`, `false` | `true` if the `exp` claim / the expiry date of the JWT should be validated |
| `auth_opt_jwt_validate_sub_match_username` | _(default)_ `true`, `false` | `true` if the MQTT username has to be the same as specified in the `sub` claim |

## Custom Claims

* `publ` _(Optional)_ Contains the Topics(filters) the client is allowed to publish in
* `subs` _(Optional)_ Contains the Topics(filters) the client is allowed to subscribe to


      {
        "sub": "mqttUser",
        "iat": 1516239022,
        "exp": 1616239022,
        "subs": ["/+/topic", "/abc/#"],
        "publ": ["/abc"]
      }
