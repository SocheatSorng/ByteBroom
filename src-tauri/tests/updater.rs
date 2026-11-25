//! The updater refuses anything not signed by the configured key (phase 6, owner's decision 2).
//!
//! Each test signs a fake installer with a throwaway minisign key made at test time (no key is
//! ever stored in the repo) and runs it through the plugin's own check, `Update::verify`, which
//! `download` and `install` both call before anything runs. No network, no install: the release
//! is handed to `restore_update` directly, so the real app needs no test endpoint or switch.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use minisign::KeyPair;
use serde_json::{Value, json};
use std::io::Cursor;
use tauri::test::{MockRuntime, mock_builder, mock_context, noop_assets};
use tauri_plugin_updater::{Error, Update, UpdaterExt};

/// What Tauri puts in `pubkey`: the minisign public key file, base64-encoded.
fn pubkey_b64(kp: &KeyPair) -> String {
    STANDARD.encode(kp.pk.to_box().unwrap().to_string())
}

/// What Tauri puts in a `.sig` file / `latest.json`: the minisign signature file, base64-encoded,
/// with the version in the trusted comment as the Tauri CLI writes it.
fn sign(kp: &KeyPair, data: &[u8], signed_version: Option<&str>) -> String {
    let mut trusted = "timestamp:1700000000\tfile:ByteBroom_setup.exe".to_string();
    if let Some(v) = signed_version {
        trusted.push_str(&format!("\tversion:{v}"));
    }
    let sig = minisign::sign(
        Some(&kp.pk),
        &kp.sk,
        Cursor::new(data),
        Some(&trusted),
        None,
    )
    .unwrap();
    STANDARD.encode(sig.to_string())
}

fn app_with(updater_config: Value) -> tauri::App<MockRuntime> {
    let mut ctx = mock_context(noop_assets());
    ctx.config_mut()
        .plugins
        .0
        .insert("updater".into(), updater_config);
    mock_builder()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .build(ctx)
        .unwrap()
}

fn app_trusting(pubkey: &str) -> tauri::App<MockRuntime> {
    app_with(json!({
        "pubkey": pubkey,
        "endpoints": ["https://example.invalid/latest.json"],
        "requireSignedVersion": true
    }))
}

/// A release as `latest.json` announces it.
fn release(app: &tauri::App<MockRuntime>, version: &str, signature: &str) -> Update {
    app.updater()
        .unwrap()
        .restore_update(json!({
            "version": version,
            "platforms": {
                "windows-x86_64": {
                    "url": "https://example.invalid/ByteBroom_setup.exe",
                    "signature": signature
                }
            }
        }))
        .unwrap()
        .expect("a higher version is an update")
}

const SETUP: &[u8] = b"pretend this is ByteBroom_9.9.9_x64-setup.exe";

#[test]
fn a_correctly_signed_update_passes() {
    let owner = KeyPair::generate_unencrypted_keypair().unwrap();
    let app = app_trusting(&pubkey_b64(&owner));
    let update = release(&app, "9.9.9", &sign(&owner, SETUP, Some("9.9.9")));
    update.verify(SETUP).unwrap();
}

#[test]
fn a_tampered_installer_is_refused() {
    let owner = KeyPair::generate_unencrypted_keypair().unwrap();
    let app = app_trusting(&pubkey_b64(&owner));
    let update = release(&app, "9.9.9", &sign(&owner, SETUP, Some("9.9.9")));
    let mut tampered = SETUP.to_vec();
    tampered[0] ^= 1;
    assert!(matches!(update.verify(&tampered), Err(Error::Minisign(_))));
}

#[test]
fn an_update_signed_by_another_key_is_refused() {
    let owner = KeyPair::generate_unencrypted_keypair().unwrap();
    let attacker = KeyPair::generate_unencrypted_keypair().unwrap();
    let app = app_trusting(&pubkey_b64(&owner));
    let update = release(&app, "9.9.9", &sign(&attacker, SETUP, Some("9.9.9")));
    assert!(matches!(update.verify(SETUP), Err(Error::Minisign(_))));
}

#[test]
fn an_old_release_announced_as_new_is_refused() {
    // A crafted latest.json pairing a new number with an older, genuinely signed installer.
    let owner = KeyPair::generate_unencrypted_keypair().unwrap();
    let app = app_trusting(&pubkey_b64(&owner));
    let update = release(&app, "9.9.9", &sign(&owner, SETUP, Some("1.0.0")));
    assert!(matches!(
        update.verify(SETUP),
        Err(Error::SignedVersionMismatch { .. })
    ));
    let unversioned = release(&app, "9.9.9", &sign(&owner, SETUP, None));
    assert!(matches!(
        unversioned.verify(SETUP),
        Err(Error::MissingSignedVersion)
    ));
}

#[test]
fn garbage_signatures_are_refused() {
    let owner = KeyPair::generate_unencrypted_keypair().unwrap();
    let app = app_trusting(&pubkey_b64(&owner));
    for sig in [
        "",
        "not base64!",
        &STANDARD.encode("not a minisign signature"),
    ] {
        let update = release(&app, "9.9.9", sig);
        assert!(update.verify(SETUP).is_err(), "{sig:?}");
    }
}

/// The real configuration: the key in `tauri.conf.json` refuses an update signed by any other key.
#[test]
fn the_shipped_key_refuses_an_update_it_did_not_sign() {
    let conf: Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).expect("tauri.conf.json");
    let app = app_with(conf["plugins"]["updater"].clone());
    let stranger = KeyPair::generate_unencrypted_keypair().unwrap();
    let update = release(&app, "9.9.9", &sign(&stranger, SETUP, Some("9.9.9")));
    assert!(matches!(update.verify(SETUP), Err(Error::Minisign(_))));
}

/// Security review S5: an older or equal version is never offered (the default comparator; no
/// override exists in the app, see `tests/boundary.rs`).
#[test]
fn an_older_or_equal_version_is_never_offered() {
    let owner = KeyPair::generate_unencrypted_keypair().unwrap();
    let app = app_trusting(&pubkey_b64(&owner));
    let current = app.package_info().version.to_string();
    for version in ["0.0.1", current.as_str()] {
        let found = app
            .updater()
            .unwrap()
            .restore_update(json!({
                "version": version,
                "platforms": {"windows-x86_64": {
                    "url": "https://example.invalid/ByteBroom_setup.exe",
                    "signature": sign(&owner, SETUP, Some(version))
                }}
            }))
            .unwrap();
        assert!(
            found.is_none(),
            "{version} must not be offered over {current}"
        );
    }
}

/// Security review S4: the version inside the signature can't be edited, even when the
/// announcement is edited to match: the global signature covers it.
#[test]
fn an_edited_signed_version_is_refused() {
    let owner = KeyPair::generate_unencrypted_keypair().unwrap();
    let app = app_trusting(&pubkey_b64(&owner));
    let good = sign(&owner, SETUP, Some("9.9.8"));
    let text = String::from_utf8(STANDARD.decode(&good).unwrap()).unwrap();
    let edited = STANDARD.encode(text.replace("version:9.9.8", "version:9.9.9"));
    let update = release(&app, "9.9.9", &edited);
    assert!(update.verify(SETUP).is_err());
}
