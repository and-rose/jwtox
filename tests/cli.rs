use assert_cmd::Command;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use predicates::prelude::*;
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use serde::Serialize;
use serde_json::json;

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

#[test]
fn jwt_is_malformed() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("jwtox")?;

    cmd.arg("notAJwt")
        .assert()
        .failure()
        .stderr(predicate::str::contains("JWT is malformed"));

    Ok(())
}

#[test]
fn decodes_jwt() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_hs256_jwt(json!({"sub": "test"}), "secret".into());
    let mut cmd = Command::cargo_bin("jwtox")?;

    cmd.arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sub\": \"test\""));

    Ok(())
}

#[test]
fn decodes_from_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_hs256_jwt(json!({"sub": "test"}), "secret".into());

    let mut cmd = Command::cargo_bin("jwtox")?;

    cmd.write_stdin(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sub\": \"test\""));

    Ok(())
}

#[test]
fn outputs_header_only() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_hs256_jwt(json!({"sub": "test"}), "secret".into());

    let mut cmd = Command::cargo_bin("jwtox")?;

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

    let mut cmd = Command::cargo_bin("jwtox")?;

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

    let mut cmd = Command::cargo_bin("jwtox")?;

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

    let mut cmd = Command::cargo_bin("jwtox")?;

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
    let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let jwt = create_rs256_jwt(json!({"sub": "test"}), &private_key);

    let mut cmd = Command::cargo_bin("jwtox")?;

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

    let mut cmd = Command::cargo_bin("jwtox")?;

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

    let mut cmd = Command::cargo_bin("jwtox")?;

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

    let mut cmd = Command::cargo_bin("jwtox")?;

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
    let mut cmd = Command::cargo_bin("jwtox")?;

    cmd.arg("--no-color")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sub\": \"test\""));

    Ok(())
}

#[test]
fn prints_help_with_help_flag() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("jwtox")?;

    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage"));

    Ok(())
}
