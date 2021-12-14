# mosquitto-jwt-auth

![Build](https://github.com/wiomoc/mosquitto-jwt-auth/actions/workflows/build.yml/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/wiomoc/mosquitto-jwt-auth/badge.svg)](https://coveralls.io/github/wiomoc/mosquitto-jwt-auth)

Simple Plugin for Mosquitto which enables authentication and authorisation via JWT as MQTT password.

Requires at least Mosquitto v1.6.3. Tested on Mac OS and Linux.

## Building
**Prebuild** version for Linux is available [here](https://github.com/wiomoc/mosquitto-jwt-auth/releases/latest)

1. If not done yet, [install Rust](https://www.rust-lang.org/tools/install)
2. Clone `git clone git@github.com:wiomoc/mosquitto-jwt-auth.git`
3. Build `cargo build --release`, on success plugin should be located at `target/release/libmosquitto_jwt_auth.so`

## Configuration
One could choose between the basic JWT validation and the more advanced JWKS validation.
### Basic JWT validation
To enable this, the configuration property `auth_opt_jwt_alg` has to be set to the desired JWT / JWS algorithm.
The key to validate the JWT could be supplied over various ways:
* in a file: `auth_opt_jwt_sec_file` has to be set to the filename containing the key
* over an environment variable: `auth_opt_jwt_sec_env` has to be set to name of the environment variable
* directly in the config: `auth_opt_jwt_sec_base64` has to be set to the base64 encoded key
If a asymmetric algorithm is used (eg. `RS256` or `ES256`) the key has to be given in DER format. 

### JWKS validation
To enable this, the configuration property `auth_opt_jwt_jwks_file` has to be set to the filename
containing the JWK set. Note that both the JWK and the JWT have to have the keyid (`kid`) set.

#### Key rotation
If you want to implement key rotation you can update this file using a external program regularly
and reload the plugin by sending a `SIGHUP` to the mosquitto process.

Example intergrated in crontab using curl:
````shell
*/10 * * * * curl -o mosquitto_jwks.json https://my-idp.com/jwks.json && killall -SIGHUP mosquitto
````

### Properties
`auth_plugin` should point to the path of `libmosquitto_jwt_auth.so`

| Property           | Valid values | Usage |
|--------------------|------|-------|
| `auth_opt_jwt_alg` | `HS256`, `HS384`, `HS512`, `ES256`, `ES384`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`| Sets the algorithm of the JWT signature |
| `auth_opt_jwt_sec_file` | `<path to file>` | Path to the file which contains the secret used for verification of the signature.|
| `auth_opt_jwt_sec_env` | `<enviroment variable name>` | Name of the environment variable which contains the base64 encoded key used for verification of the signature. |
| `auth_opt_jwt_sec_base64` | `<base64-encoded-secret>` | Base64 encoded key used for verification of the signature. |
| `auth_opt_jwt_jwks_file` | `<path to file>` | Path to the file which contains a JWK set. |
| `auth_opt_jwt_validate_exp` | _(default)_ `true`, `false` | `true` if the `exp` claim / the expiry date of the JWT should be validated |
| `auth_opt_jwt_validate_sub_match_username` | _(default)_ `true`, `false` | `true` if the MQTT username has to be the same as specified in the `sub` claim |

## Custom Claims
The plugin authorizes subscriptions and publications based on the acl stated in JWT claims.

* `publ` _(Optional)_ Contains the Topics(filters) the client is allowed to publish in
* `subs` _(Optional)_ Contains the Topics(filters) the client is allowed to subscribe to


      {
        "sub": "mqttUser",
        "iat": 1516239022,
        "exp": 1616239022,
        "subs": ["/+/topic", "/abc/#"],
        "publ": ["/abc"]
      }
