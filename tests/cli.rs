use assert_cmd::cargo;
use assert_fs::prelude::*;
use base64::prelude::*;
use httpmock::prelude::*;
use jsonwebtoken::Header;
use predicates::prelude::*;
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use serde_json::json;
use std::sync::OnceLock;

mod jwt_helper;

use jwt_helper::JwtBuilder;

fn secs_to_date(secs: i64) -> chrono::DateTime<chrono::Local> {
    chrono::DateTime::from_timestamp(secs, 0)
        .unwrap()
        .with_timezone(&chrono::Local)
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
    let jwt = JwtBuilder::hs256(json!({"sub": "test"}), "secret").build();

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sub\": \"test\""));

    Ok(())
}

#[test]
fn decodes_from_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = JwtBuilder::hs256(json!({"sub": "test"}), "secret").build();

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.write_stdin(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sub\": \"test\""));

    Ok(())
}

#[test]
fn outputs_header_only() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = JwtBuilder::hs256(json!({"sub": "test"}), "secret").build();

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
    let jwt = JwtBuilder::hs256(json!({"sub": "test"}), "secret").build();

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
    let jwt = JwtBuilder::hs256(json!({"sub": "test"}), "secret").build();

    let file = assert_fs::NamedTempFile::new("keyfile.txt")?;
    file.write_str("secret")?;

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--key-file")
        .arg(file.path())
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature ✓"));

    Ok(())
}

#[test]
fn rejects_invalid_hs256_signature() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = JwtBuilder::hs256(json!({"sub": "test"}), "secret").build();

    let file = assert_fs::NamedTempFile::new("keyfile.txt")?;
    file.write_str("wrong_secret")?;

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--key-file")
        .arg(file.path())
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature ✗"));

    Ok(())
}

#[test]
fn refuses_validate_rs256_signature() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("Failed to generate RSA key");
    let jwt = JwtBuilder::rs256(
        json!({"sub": "test"}),
        private_key.to_pkcs1_der().unwrap().as_bytes(),
    )
    .build();

    let file = assert_fs::NamedTempFile::new("keyfile.txt")?;
    file.write_str("some_key")?;

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--key-file")
        .arg(file.path())
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

    let jwt = JwtBuilder::hs256(claims, "secret").build();

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

    let jwt = JwtBuilder::hs256(claims, "secret").build();

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

    let jwt = JwtBuilder::hs256(claims, "secret").build();

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
    let jwt = JwtBuilder::hs256(json!({"sub": "test"}), "secret").build();
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

    let jwt = JwtBuilder::hs256(claims, "secret").build();

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("⚠️ Token expired an hour ago"));

    Ok(())
}

#[test]
fn alerts_when_token_will_expire() -> Result<(), Box<dyn std::error::Error>> {
    let now = chrono::Local::now().timestamp();

    let claims = json!({
        "sub": "test",
        "iat": now,
        "exp": now + 60,
        "nbf": now,
    });

    let jwt = JwtBuilder::hs256(claims, "secret").build();

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("Token expires in a minute"));

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

    let jwt = JwtBuilder::hs256(claims, "secret").build();

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("⚠️ Token Expired").count(0));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn verifies_rsa_signature_with_jwks() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = get_static_private_key();
    let e_b64 = BASE64_URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be());
    let n_b64 = BASE64_URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be());

    let server = MockServer::start_async().await;

    let openid_mock = server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "jwks_uri": "/.well-known/jwks.json"
                })
                .to_string(),
            );
    });

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

    let jwt = JwtBuilder::rs256(
        json!({
            "sub": "test",
            "iss": server.url("/"),
        }),
        private_key.to_pkcs1_der().unwrap().as_bytes(),
    )
    .with_headers(Header {
        kid: Some("test-key".to_string()),
        ..Default::default()
    })
    .build();

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--verify-jwks")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature ✓"));

    openid_mock.assert_async().await;
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

    let jwt = JwtBuilder::rs256(
        json!({
            "sub": "test",
            "iss": server.url("/"),
        }),
        private_key.to_pkcs1_der().unwrap().as_bytes(),
    )
    .build();

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

    let jwt = JwtBuilder::rs256(
        json!({
            "sub": "test",
        }),
        private_key.to_pkcs1_der().unwrap().as_bytes(),
    )
    .with_headers(Header {
        kid: Some("test-key".to_string()),
        ..Default::default()
    })
    .build();

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

#[tokio::test(flavor = "multi_thread")]
async fn stores_http_response_in_cache() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start_async().await;

    let openid_mock = server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "jwks_uri": "/.well-known/jwks.json"
                })
                .to_string(),
            );
    });

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
                            "n": BASE64_URL_SAFE_NO_PAD.encode(get_static_private_key().n().to_bytes_be()),
                            "e": BASE64_URL_SAFE_NO_PAD.encode(get_static_private_key().e().to_bytes_be())
                        }
                    ]
                })
                .to_string(),
            );
    });

    let jwt = JwtBuilder::rs256(
        json!({
            "sub": "test",
            "iss": server.url("/"),
        }),
        get_static_private_key().to_pkcs1_der().unwrap().as_bytes(),
    )
    .with_headers(Header {
        kid: Some("test-key".to_string()),
        ..Default::default()
    })
    .build();

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--verify-jwks")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature ✓"));

    // Assert that the JWKS endpoint was called
    openid_mock.assert_async().await;
    jwks_mock.assert_async().await;

    // Assert that the cache file was created
    let cache_dir = dirs::cache_dir().unwrap().join("jwtox");
    let cache_key = format!(
        "{:x}",
        md5::compute(server.url("/.well-known/jwks.json").as_str())
    );
    let cache_file = cache_dir.join(format!("{}.json", cache_key));

    assert!(cache_file.exists());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn follows_openid_configuration() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start_async().await;

    let openid_mock = server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "jwks_uri": "/a-very-different-path/strange.json"
                })
                .to_string(),
            );
    });

    let jwks_mock = server.mock(|when, then| {
        when.method(GET).path("/a-very-different-path/strange.json");
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
                            "n": BASE64_URL_SAFE_NO_PAD.encode(get_static_private_key().n().to_bytes_be()),
                            "e": BASE64_URL_SAFE_NO_PAD.encode(get_static_private_key().e().to_bytes_be())
                        }
                    ]
                })
                .to_string(),
            );
    });

    let jwt = JwtBuilder::rs256(
        json!({
            "sub": "test",
            "iss": server.url("/"),
        }),
        get_static_private_key().to_pkcs1_der().unwrap().as_bytes(),
    )
    .with_headers(Header {
        kid: Some("test-key".to_string()),
        ..Default::default()
    })
    .build();

    let mut cmd = cargo::cargo_bin_cmd!("jwtox");

    cmd.arg("--verify-jwks").arg(jwt).assert().success();

    openid_mock.assert_async().await;
    jwks_mock.assert_async().await;

    Ok(())
}
