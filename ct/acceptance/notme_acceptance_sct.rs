//! notme acceptance, step 1 (notme-1b46a8): do the embedded SCTs in a pair
//! minted through notme's real /cert/gha route VERIFY under azul's own
//! `sct_validator`?
//!
//! NOT AN AZUL TEST. Lives in notme (ct/acceptance/) and is copied into a
//! throwaway azul worktree's crates/sct_validator/tests/ by
//! ct/scripts/acceptance.sh, run, and removed. Modelled on the spike's
//! notme_embedded_sct.rs (azul branch notme-ct-spike, ee88217).
//!
//! Inputs (env): NOTME_ACCEPT_DIR holding log.json (log_id, key: base64),
//! issuer.pem, step1-mtls.pem, step1-signing.pem, step2-mtls.pem.
//!
//! WHAT PASSING MEANS: notme runs one log, so Chrome's two-operator policy
//! makes `Valid` unreachable. azul drops an SCT whose signature fails before
//! the policy check (lib.rs `continue`), so `NotEnoughCompliantSCTs { found }`
//! counts SCTs whose signature VERIFIED over azul's own RFC 6962 §3.2
//! reconstruction. Each certificate carries one SCT, so found must be 1.
//! Two controls keep that reading honest: a different real P-256 key drops
//! the count to 0, and the step-2 certificate (minted while the log was down,
//! so no SCT list) is refused.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sct_validator::{CtLog, CtLogList, LogState, SctValidationResult, SctValidator};
use std::path::PathBuf;
use x509_cert::{Certificate, der::DecodePem, der::Encode};

fn dir() -> PathBuf {
    PathBuf::from(std::env::var("NOTME_ACCEPT_DIR").expect("NOTME_ACCEPT_DIR must be set"))
}

fn cert(name: &str) -> (Vec<u8>, u64) {
    let pem = std::fs::read(dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    let c = Certificate::from_pem(&pem).expect("parse pem");
    // Validate inside the certificate's own life (it lives minutes), so the
    // result does not depend on when this runs relative to the mint.
    let v = c.tbs_certificate().validity();
    let at = (v.not_before.to_unix_duration().as_secs() + v.not_after.to_unix_duration().as_secs()) / 2;
    (c.to_der().expect("der"), at)
}

fn log_list(key_b64: &str, at: u64) -> CtLogList {
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir().join("log.json")).expect("log.json")).unwrap();
    let id: [u8; 32] = STANDARD
        .decode(meta["log_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .expect("32-byte log id");
    let key = STANDARD.decode(key_b64).expect("key b64");
    let mut list = CtLogList::new(at);
    let log = CtLog::new("notme local".into(), id, &key, LogState::Usable, 0, "notme".into(), vec![])
        .expect("construct log");
    list.logs.insert(id, log);
    list
}

fn real_key() -> String {
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir().join("log.json")).unwrap()).unwrap();
    meta["key"].as_str().unwrap().to_string()
}

fn verified(leaf: &str, key_b64: &str) -> usize {
    let (leaf, at) = cert(leaf);
    let (issuer, _) = cert("issuer.pem");
    let r = SctValidator::new(log_list(key_b64, at)).validate_embedded_scts(&leaf, &issuer, at);
    println!("validate_embedded_scts -> {r:?}");
    match &r {
        Ok(SctValidationResult::Valid | SctValidationResult::ValidWithWarnings(_)) => 1,
        Err(sct_validator::SctError::Policy(
            sct_validator::PolicyError::NotEnoughCompliantSCTs { found, .. },
        )) => *found,
        _ => 0,
    }
}

#[test]
fn step1_mtls_cert_embedded_sct_verifies() {
    assert_eq!(verified("step1-mtls.pem", &real_key()), 1);
}

#[test]
fn step1_signing_cert_embedded_sct_verifies() {
    assert_eq!(verified("step1-signing.pem", &real_key()), 1);
}

#[test]
fn control_a_different_key_verifies_nothing() {
    // A real, parseable P-256 key that did not sign these SCTs (the spike's).
    let other = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE//II4I3M5fpVXhR8KFGOxZsO7y5Aje83VzrX9ve5zHweke49SevN3sjbri/NyliZ/dkCm5GqEDdoBCiIzzDcng==";
    assert_ne!(other, real_key());
    assert_eq!(verified("step1-mtls.pem", other), 0);
    assert_eq!(verified("step1-signing.pem", other), 0);
}

#[test]
fn control_the_unlogged_step2_cert_is_refused() {
    let (leaf, at) = cert("step2-mtls.pem");
    let (issuer, _) = cert("issuer.pem");
    let r = SctValidator::new(log_list(&real_key(), at)).validate_embedded_scts(&leaf, &issuer, at);
    println!("validate_embedded_scts(step2) -> {r:?}");
    assert!(r.is_err(), "a certificate with no SCT list must be refused: {r:?}");
}
