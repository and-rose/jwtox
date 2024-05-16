use assert_cmd::Command;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use predicates::prelude::*;
use serde::Serialize;
use serde_json::json;

fn create_jwt<T: Serialize>(claims: T, algorithm: Algorithm, key: String) -> String {
    let header = Header::new(algorithm);

    encode(&header, &claims, &EncodingKey::from_secret(key.as_ref())).unwrap()
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
    let jwt = create_jwt(json!({"sub": "test"}), Algorithm::HS256, "secret".into());
    let mut cmd = Command::cargo_bin("jwtox")?;

    cmd.arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sub\": \"test\""));

    Ok(())
}

#[test]
fn decodes_from_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_jwt(json!({"sub": "test"}), Algorithm::HS256, "secret".into());

    let mut cmd = Command::cargo_bin("jwtox")?;

    cmd.write_stdin(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sub\": \"test\""));

    Ok(())
}

#[test]
fn outputs_header_only() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_jwt(json!({"sub": "test"}), Algorithm::HS256, "secret".into());

    let mut cmd = Command::cargo_bin("jwtox")?;

    cmd.arg("--header-only")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"alg\": \"HS256\""));

    Ok(())
}

#[test]
fn outputs_payload_only() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_jwt(json!({"sub": "test"}), Algorithm::HS256, "secret".into());

    let mut cmd = Command::cargo_bin("jwtox")?;

    cmd.arg("--payload-only")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sub\": \"test\""));

    Ok(())
}

#[test]
fn verifies_valid_hs256_signature() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = create_jwt(json!({"sub": "test"}), Algorithm::HS256, "secret".into());

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
    let jwt = create_jwt(json!({"sub": "test"}), Algorithm::HS256, "secret".into());

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
fn issued_at_no_calc() -> Result<(), Box<dyn std::error::Error>> {
    let now = chrono::Local::now();
    let now_seconds = now.timestamp();
    let claims = json!({
        "sub": "test",
        "iat": now_seconds,
        "exp": now_seconds + 3600,
        "nbf": now_seconds,
    });

    let jwt = create_jwt(claims, Algorithm::HS256, "secret".into());

    let mut cmd = Command::cargo_bin("jwtox")?;

    cmd.arg("--no-calc")
        .arg(jwt)
        .assert()
        .success()
        .stdout(predicate::str::contains(now.to_rfc2822()).count(0));

    Ok(())
}

#[test]
fn friendly_date_displays() -> Result<(), Box<dyn std::error::Error>> {
    let now = chrono::Local::now().timestamp();
    fn secs_to_date(secs: i64) -> chrono::DateTime<chrono::Local> {
        chrono::DateTime::from_timestamp(secs, 0)
            .unwrap()
            .with_timezone(&chrono::Local)
    }

    let claims = json!({
        "sub": "test",
        "iat": now,
        "exp": now + 3600,
        "nbf": now,
    });

    let jwt = create_jwt(claims, Algorithm::HS256, "secret".into());

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

    let jwt = create_jwt(claims, Algorithm::HS256, "secret".into());

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
    let jwt = create_jwt(json!({"sub": "test"}), Algorithm::HS256, "secret".into());
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
