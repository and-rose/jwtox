use assert_cmd::cargo;
use base64::prelude::*;
use httpmock::prelude::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use predicates::prelude::*;
use rsa::RsaPrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use serde::Serialize;
use serde_json::json;
use std::sync::OnceLock;

fn secs_to_date(secs: i64) -> chrono::DateTime<chrono::Local> {
    chrono::DateTime::from_timestamp(secs, 0)
        .unwrap()
        .with_timezone(&chrono::Local)
}

fn create_hs256_jwt<T: Serialize>(claims: T, key: String) -> String {
    let header = Header::new(Algorithm::HS256);

    encode(&header, &claims, &EncodingKey::from_secret(key.as_ref())).unwrap()
}

fn create_rs256_jwt<T: Serialize>(claims: T, key: &RsaPrivateKey) -> String {
    let header = Header::new(Algorithm::RS256);
    let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::default()).unwrap();

    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn create_rs256_jwt_with_kid<T: Serialize>(claims: T, key: &RsaPrivateKey, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::default()).unwrap();

    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap()
}

static TEST_KEY: OnceLock<RsaPrivateKey> = OnceLock::new();

fn get_static_private_key() -> &'static RsaPrivateKey {
    TEST_KEY
        .get_or_init(|| RsaPrivateKey::new(&mut OsRng, 2048).expect("Failed to generate RSA key"))
}

#[test]
fn jwt_is_malformed() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("notAJwt")
        .assert()
        .failure()
        .stderr(predicate::str::contains("JWT is malformed"));

    Ok(())
}

#[test]
fn decodes_jwt() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_hs256_jwt(json!({"sub": "test"}), "secret".into());
    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sub\": \"test\""));

    Ok(())
}

#[test]
fn decodes_from_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_hs256_jwt(json!({"sub": "test"}), "secret".into());

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.write_stdin(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sub\": \"test\""));

    Ok(())
}

#[test]
fn outputs_header_only() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_hs256_jwt(json!({"sub": "test"}), "secret".into());

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--header-only")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"alg\": \"HS256\""))
        .stdout(predicate::str::contains("\"typ\": \"JWT\""))
        .stdout(predicate::str::contains("\"sub\": \"test\"").count(0));

    Ok(())
}

#[test]
fn outputs_payload_only() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_hs256_jwt(json!({"sub": "test"}), "secret".into());

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--payload-only")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sub\": \"test\""))
        .stdout(predicate::str::contains("\"alg\": \"HS256\"").count(0))
        .stdout(predicate::str::contains("\"typ\": \"JWT\"").count(0));

    Ok(())
}

#[test]
fn verifies_valid_hs256_signature() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_hs256_jwt(json!({"sub": "test"}), "secret".into());

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--key")
        .arg("secret")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature ✓"));

    Ok(())
}

#[test]
fn rejects_invalid_hs256_signature() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_hs256_jwt(json!({"sub": "test"}), "secret".into());

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--key")
        .arg("wrong_secret")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature ✗"));

    Ok(())
}

#[test]
fn refuses_validate_rs256_signature() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("Failed to generate RSA key");
    let jwt = create_rs256_jwt(json!({"sub": "test"}), &private_key);

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--key")
        .arg("some_key")
        .arg(jwt)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Algorithm not supported"));

    Ok(())
}

#[test]
fn issued_at_no_calc() -> Result<(), Box<dyn std::error::Error>> {
    let now = chrono::Local::now().timestamp();
    let claims = json!({
        "sub": "test",
        "iat": now,
        "exp": now + 3600,
        "nbf": now,
    });

    let jwt = create_hs256_jwt(claims, "secret".into());

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--no-calc")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains(secs_to_date(now).to_string()).count(0));

    Ok(())
}

#[test]
fn friendly_date_displays() -> Result<(), Box<dyn std::error::Error>> {
    let now = chrono::Local::now().timestamp();

    let claims = json!({
        "sub": "test",
        "iat": now,
        "exp": now + 3600,
        "nbf": now,
    });

    let jwt = create_hs256_jwt(claims, "secret".into());

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "iat: {} {}",
            now,
            secs_to_date(now)
        )))
        .stdout(predicate::str::contains(format!(
            "exp: {} {}",
            now + 3600,
            secs_to_date(now + 3600)
        )))
        .stdout(predicate::str::contains(format!(
            "nbf: {} {}",
            now,
            secs_to_date(now)
        )));

    Ok(())
}

#[test]
fn utc_date_displays() -> Result<(), Box<dyn std::error::Error>> {
    let now = chrono::Local::now().timestamp();
    fn secs_to_date(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(secs, 0)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    let claims = json!({
        "sub": "test",
        "iat": now,
        "exp": now + 3600,
        "nbf": now,
    });

    let jwt = create_hs256_jwt(claims, "secret".into());

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--utc")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "iat: {} {}",
            now,
            secs_to_date(now)
        )))
        .stdout(predicate::str::contains(format!(
            "exp: {} {}",
            now + 3600,
            secs_to_date(now + 3600)
        )))
        .stdout(predicate::str::contains(format!(
            "nbf: {} {}",
            now,
            secs_to_date(now)
        )));

    Ok(())
}

#[test]
fn decodes_jwt_with_no_color() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_hs256_jwt(json!({"sub": "test"}), "secret".into());
    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--no-color")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sub\": \"test\""));

    Ok(())
}

#[test]
fn prints_help_with_help_flag() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage"));

    Ok(())
}

#[test]
fn alerts_when_token_is_expired() -> Result<(), Box<dyn std::error::Error>> {
    let now = chrono::Local::now().timestamp();

    let claims = json!({
        "sub": "test",
        "iat": now - 7200,
        "exp": now - 3600,
        "nbf": now - 7200,
    });

    let jwt = create_hs256_jwt(claims, "secret".into());

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("⚠️ Token Expired"));

    Ok(())
}

#[test]
fn does_not_alert_when_token_is_not_expired() -> Result<(), Box<dyn std::error::Error>> {
    let now = chrono::Local::now().timestamp();

    let claims = json!({
        "sub": "test",
        "iat": now,
        "exp": now + 3600,
        "nbf": now,
    });

    let jwt = create_hs256_jwt(claims, "secret".into());

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("⚠️ Token Expired").count(0));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn verifies_signature_with_jwks() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = get_static_private_key();
    let e_b64 = BASE64_URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be());
    let n_b64 = BASE64_URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be());

    let server = MockServer::start_async().await;

    let jwks_mock = server.mock(|when, then| {
        when.method(GET).path("/.well-known/jwks.json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "keys": [
                        {
                            "kty": "RSA",
                            "kid": "test-key",
                            "use": "sig",
                            "alg": "RS256",
                            "n": n_b64,
                            "e": e_b64
                        }
                    ]
                })
                .to_string(),
            );
    });

    let jwt = create_rs256_jwt_with_kid(
        json!({
            "sub": "test",
            "iss": server.url("/"),
        }),
        private_key,
        "test-key",
    );

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--verify-jwks")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature ✓"));

    jwks_mock.assert_async().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn fails_verification_with_jwks_when_kid_missing() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = get_static_private_key();
    let e_b64 = BASE64_URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be());
    let n_b64 = BASE64_URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be());

    let server = MockServer::start_async().await;

    server.mock(|when, then| {
        when.method(GET).path("/.well-known/jwks.json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "keys": [
                        {
                            "kty": "RSA",
                            "use": "sig",
                            "alg": "RS256",
                            "n": n_b64,
                            "e": e_b64
                        }
                    ]
                })
                .to_string(),
            );
    });

    let jwt = create_rs256_jwt(
        json!({
            "sub": "test",
            "iss": server.url("/"),
        }),
        private_key,
    );

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--verify-jwks")
        .arg(jwt)
        .assert()
        .failure()
        .stderr(predicate::str::contains("kid header is missing"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn fails_verification_with_jwks_when_iss_missing() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = get_static_private_key();
    let e_b64 = BASE64_URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be());
    let n_b64 = BASE64_URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be());

    let server = MockServer::start_async().await;

    server.mock(|when, then| {
        when.method(GET).path("/.well-known/jwks.json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "keys": [
                        {
                            "kty": "RSA",
                            "kid": "test-key",
                            "use": "sig",
                            "alg": "RS256",
                            "n": n_b64,
                            "e": e_b64
                        }
                    ]
                })
                .to_string(),
            );
    });

    let jwt = create_rs256_jwt_with_kid(
        json!({
            "sub": "test",
        }),
        private_key,
        "test-key",
    );

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--verify-jwks")
        .arg(jwt)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "iss claim is missing or not a URL",
        ));

    Ok(())
}
