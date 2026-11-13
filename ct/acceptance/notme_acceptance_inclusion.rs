//! notme acceptance, step 3 (notme-1b46a8): after the outage, did the
//! refresh alarm's drain put notme's final certificates INTO the log?
//!
//! NOT AN AZUL TEST. Lives in notme (ct/acceptance/) and is copied into a
//! throwaway azul worktree's crates/integration_tests/tests/ by
//! ct/scripts/acceptance.sh, run, and removed.
//!
//! Static CT has no get-entries: the log's read path is its tiles and its
//! signed checkpoint. Locally those live in wrangler's persisted R2 state and
//! azul's own `CtClient::get_raw` reads them (`wrangler r2 object get
//! --local`). So this uses azul's own client and assertions:
//!
//!   1. fetch the checkpoint and verify its signature (log key from
//!      metadata.json);
//!   2. scan every data tile for an X509 (add-chain) entry whose certificate
//!      is byte-identical to the drained certificate;
//!   3. prove that entry's Merkle inclusion under the checkpoint root
//!      (`assert_leaf_in_checkpoint`).
//!
//! Control: a step-1 final certificate was logged only as a PRECERT (its
//! TBS, via add-pre-chain) and never add-chained, so it must NOT be found as
//! an X509 entry — otherwise the scan would match anything.
//!
//! Inputs (env): NOTME_ACCEPT_DIR (step2-mtls.pem, step2-signing.pem,
//! step1-mtls.pem), BASE_URL (http://localhost:8787), LOG_NAME (notmedev).

use integration_tests::{
    assertions::{VerifiedCheckpoint, assert_leaf_in_checkpoint, fetch_and_verify_checkpoint},
    client::CtClient,
};
use static_ct_api::StaticCTLogEntry;
use std::path::PathBuf;
use tlog_entry::TileIterator;
use tlog_tiles::{PathElem, TlogTile};
use x509_cert::{Certificate, der::DecodePem, der::Encode};

fn der(name: &str) -> Vec<u8> {
    let d = PathBuf::from(std::env::var("NOTME_ACCEPT_DIR").expect("NOTME_ACCEPT_DIR must be set"));
    let pem = std::fs::read(d.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_pem(&pem).expect("pem").to_der().expect("der")
}

/// The leaf index of an X509 entry carrying exactly `cert`, if any.
async fn find_x509(client: &CtClient, cp: &VerifiedCheckpoint, cert: &[u8]) -> Option<u64> {
    let size = cp.text.size();
    let full = u64::from(TlogTile::FULL_WIDTH);
    for n in 0..size.div_ceil(full) {
        let width = u32::try_from((size - n * full).min(full)).unwrap();
        let path = TlogTile::new(0, n, width, Some(PathElem::Data)).path();
        let bytes = client.get_raw(&path).await.expect("data tile");
        for e in TileIterator::<StaticCTLogEntry>::new(&bytes, width as usize) {
            let e = e.expect("parse tile entry");
            if e.inner.precert_opt.is_none() && e.inner.certificate == cert {
                return Some(e.leaf_index);
            }
        }
    }
    None
}

#[tokio::test]
async fn drained_certs_are_in_the_signed_tree() {
    let client = CtClient::default_log();
    let meta = client.get_metadata().await.expect("metadata.json");
    let cp = fetch_and_verify_checkpoint(&client, &meta, None).await.expect("verified checkpoint");
    println!("checkpoint verified: log {} tree_size {}", client.log, cp.text.size());

    for name in ["step2-mtls.pem", "step2-signing.pem"] {
        let idx = find_x509(&client, &cp, &der(name))
            .await
            .unwrap_or_else(|| panic!("{name}: no X509 entry in the log carries this certificate"));
        assert_leaf_in_checkpoint(&client, &cp, idx)
            .await
            .unwrap_or_else(|e| panic!("{name}: leaf {idx} not proven in the checkpoint: {e:#}"));
        println!("{name}: X509 entry at leaf_index {idx}, Merkle inclusion verified");
    }

    // Control: never add-chained, so never an X509 entry.
    assert_eq!(
        find_x509(&client, &cp, &der("step1-mtls.pem")).await,
        None,
        "the scan matched a certificate that was never submitted to add-chain"
    );
    println!("control: step1-mtls.pem (precert-logged only) has no X509 entry");
}
