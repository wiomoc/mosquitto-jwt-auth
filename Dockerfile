FROM eclipse-mosquitto:2.0.15-openssl AS build

# use the mosquitto image to keep the alpine version in sync
# https://github.com/eclipse/mosquitto/blob/master/docker/2.0-openssl/Dockerfile

RUN apk upgrade
RUN apk add rust cargo

ADD . /mosquitto-jwt-auth
WORKDIR /mosquitto-jwt-auth

RUN cargo build --release

FROM eclipse-mosquitto:2.0.15-openssl
RUN apk add libgcc
COPY --from=build /mosquitto-jwt-auth/target/release/libmosquitto_jwt_auth.so /usr/lib/
