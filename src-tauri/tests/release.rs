//! The release script and its independent check (phase 6, owner's decisions 3 and 4).
//!
//! `release.ps1` signs on the owner's PC with a key kept outside the repo and the password typed
//! at the prompt; `tools/verify-release.mjs` re-checks every release in Node before upload. The
//! last tests sign with Rust's `minisign` and verify with the Node script, so the two
//! implementations have to agree.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use minisign::KeyPair;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn release_ps1_signs_locally_with_the_owners_key_and_checks_the_result() {
    let script = read("release.ps1");
    for must in [
        // the key outside every repo, and its public half must match the shipped one
        "Join-Path $env:LOCALAPPDATA 'ByteBroom-signing'",
        "'bytebroom.key'",
        "-ne $conf.plugins.updater.pubkey",
        // a clean commit (and git really answered), the full checks, then build.ps1's installer
        "git status --porcelain",
        "if ($LASTEXITCODE -ne 0) { throw 'git could not read",
        "check.ps1",
        "build.ps1",
        // the owner types the password; it lives only in this process and is removed again
        "Read-Host -AsSecureString",
        "Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
        "Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY_PATH",
        "ZeroFreeBSTR",
        // the signature is bound to the version (requireSignedVersion)
        "cargo tauri signer sign --app-version $version $setup",
        // latest.json points at this repo's release for this version, and is checked in Node
        "https://github.com/SocheatSorng/ByteBroom/releases/download/v$version/$setupName",
        "node tools/verify-release.mjs $latestPath $setup",
    ] {
        assert!(script.contains(must), "release.ps1 lacks {must}");
    }
    // Nothing is uploaded or published from the script (the owner uploads in the browser).
    for never in [
        "Invoke-WebRequest",
        "Invoke-RestMethod",
        "curl",
        "gh ",
        "git push",
        "git tag",
    ] {
        assert!(!script.contains(never), "release.ps1 must not use {never}");
    }
    // Security review S1: every build runs before any secret is set, and while the secrets are
    // set only the signer runs (no cargo build, no build scripts, no other program).
    let set = script
        .find("$env:TAURI_SIGNING_PRIVATE_KEY_PATH = ")
        .expect("the key path is set for the signer");
    let before = &script[..set];
    assert!(before.contains("& (Join-Path $PSScriptRoot 'build.ps1')"));
    assert!(
        !before.contains("$env:TAURI_SIGNING"),
        "no secret before the build"
    );
    let (inside, after) = script[set..]
        .split_once("} finally {")
        .expect("a finally block");
    let commands: Vec<&str> = inside
        .lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with('#')
                && !l.starts_with("$env:")
                && !l.starts_with("$code")
        })
        .collect();
    assert_eq!(
        commands,
        ["cargo tauri signer sign --app-version $version $setup"],
        "only the signer runs while the secrets are set"
    );
    assert!(after.contains("TAURI_SIGNING_PRIVATE_KEY_PASSWORD"));
    assert!(after.contains("TAURI_SIGNING_PRIVATE_KEY_PATH"));
    assert!(!script.contains("createUpdaterArtifacts"));
}

/// build.ps1 (which release.ps1 runs): no user folder in the binaries, and a stale staged helper
/// can never be packed (security review S6, S7).
#[test]
fn build_scrubs_the_user_folder_and_packs_only_the_fresh_helper() {
    let common = read("tools/build-common.ps1");
    assert!(common.contains("--remap-path-prefix=$($env:USERPROFILE)=~"));
    assert!(
        common.contains(
            "Copy-Item -LiteralPath $built -Destination $staged -Force -ErrorAction Stop"
        )
    );
    assert!(common.contains("if ($a -ne $b) { throw"));
    assert!(common.contains("[Text.Encoding]::Unicode.GetString($bytes, 1"));
    let build = read("build.ps1");
    for must in [
        ". (Join-Path $PSScriptRoot 'tools\\build-common.ps1')",
        "Set-NoProfilePathsInBinaries",
        "Copy-StagedHelper $PSScriptRoot",
        "Assert-StagedHelperMatches $PSScriptRoot",
        "Assert-NoProfilePath",
        "$env:RUSTFLAGS = $savedFlags",
    ] {
        assert!(build.contains(must), "build.ps1 lacks {must}");
    }
    // The checks come after the bundle that could have changed things.
    let bundle = build.find("cargo tauri build").unwrap();
    assert!(build.find("Assert-StagedHelperMatches").unwrap() > bundle);
    assert!(build.find("Assert-NoProfilePath (").unwrap() > bundle);
}

/// CI builds the same unsigned installer as `build.ps1` and checks its generated script, but
/// never signs: the key stays on the owner's PC (owner's decision 3, task 8).
#[test]
fn ci_builds_the_unsigned_installer_and_never_signs() {
    let ci = read(".github/workflows/ci.yml");
    assert!(ci.contains("cargo install --locked tauri-cli --version"));
    let build = ci
        .find("run: ./build.ps1")
        .expect("ci.yml runs ./build.ps1");
    let after = ci
        .find("cargo test -p bytebroom-app --test installer")
        .expect("ci.yml checks the built installer script");
    assert!(after > build, "the installer test runs after the build");
    for wf in ["ci.yml", "security.yml", "codeql.yml"] {
        let text = read(&format!(".github/workflows/{wf}"));
        for never in ["TAURI_SIGNING", "signer", "secrets."] {
            assert!(!text.contains(never), "{wf} mentions {never}");
        }
    }
}

/// Sign `data` as the Tauri CLI does (prehashed, version in the trusted comment), base64-encoded.
fn tauri_sig(kp: &KeyPair, data: &[u8], version: &str) -> String {
    let trusted = format!("timestamp:1700000000\tfile:ByteBroom_setup.exe\tversion:{version}");
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

/// Run the Node verifier's `check` on a made-up release; true when it accepts it.
fn node_accepts(dir: &Path, pubkey: &str, setup: &[u8], sig: &str, version: &str) -> bool {
    let url = format!(
        "https://github.com/SocheatSorng/ByteBroom/releases/download/v{version}/ByteBroom_setup.exe"
    );
    node_accepts_at(dir, pubkey, setup, sig, version, &url)
}

fn node_accepts_at(
    dir: &Path,
    pubkey: &str,
    setup: &[u8],
    sig: &str,
    version: &str,
    url: &str,
) -> bool {
    let latest = serde_json::json!({
        "version": version,
        "platforms": {"windows-x86_64": {"signature": sig, "url": url}}
    });
    fs::write(dir.join("latest.json"), latest.to_string()).unwrap();
    fs::write(dir.join("setup.exe"), setup).unwrap();
    fs::write(dir.join("key.pub"), pubkey).unwrap();
    let verifier = root().join("tools").join("verify-release.mjs");
    let script = r#"
        import { readFileSync } from "node:fs";
        import { pathToFileURL } from "node:url";
        const dir = process.argv[1];
        const { check } = await import(pathToFileURL(process.env.BB_VERIFIER).href);
        check(JSON.parse(readFileSync(dir + "/latest.json", "utf8")),
              readFileSync(dir + "/setup.exe"), readFileSync(dir + "/key.pub", "utf8"));
    "#;
    let out = Command::new("node")
        .args(["--input-type=module", "-e", script])
        // Not as an argument: the script runs as a command when argv[1] names it.
        .env("BB_VERIFIER", &verifier)
        .arg(dir)
        .output()
        .expect("node is needed for this test (it is on the CI runner)");
    if !out.status.success() {
        // Shown only when a test fails: what the Node check refused, and why.
        let _ = std::io::Write::write_all(&mut std::io::stderr(), &out.stdout);
        let _ = std::io::Write::write_all(&mut std::io::stderr(), &out.stderr);
    }
    out.status.success()
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bytebroom-release-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn rust_signatures_pass_the_node_check_and_tampering_does_not() {
    let dir = temp_dir("node");
    let owner = KeyPair::generate_unencrypted_keypair().unwrap();
    let other = KeyPair::generate_unencrypted_keypair().unwrap();
    let pubkey = STANDARD.encode(owner.pk.to_box().unwrap().to_string());
    let setup = b"pretend installer bytes".to_vec();
    let good = tauri_sig(&owner, &setup, "1.0.0");

    assert!(node_accepts(&dir, &pubkey, &setup, &good, "1.0.0"));
    let mut tampered = setup.clone();
    tampered[0] ^= 1;
    assert!(!node_accepts(&dir, &pubkey, &tampered, &good, "1.0.0"));
    assert!(!node_accepts(
        &dir,
        &pubkey,
        &setup,
        &tauri_sig(&other, &setup, "1.0.0"),
        "1.0.0"
    ));
    assert!(
        !node_accepts(&dir, &pubkey, &setup, &good, "1.0.1"),
        "signed version must match"
    );
    assert!(
        !node_accepts(&dir, &pubkey, &setup, &good, "v1.0.0"),
        "no looser than the updater"
    );

    // Security review S4: an edited trusted comment (the version) breaks the global signature,
    // even when latest.json is edited to match.
    let edited = edit_signature(&good, |lines| {
        lines[2] = lines[2].replace("version:1.0.0", "version:1.0.1")
    });
    assert!(!node_accepts(&dir, &pubkey, &setup, &edited, "1.0.1"));
    // Another key id in the signature.
    let other_id = edit_signature(&good, |lines| {
        let mut raw = STANDARD.decode(&lines[1]).unwrap();
        raw[2] ^= 1;
        lines[1] = STANDARD.encode(raw);
    });
    assert!(!node_accepts(&dir, &pubkey, &setup, &other_id, "1.0.0"));
    // Downloads only from this repo's release of exactly this version.
    for url in [
        "https://github.com/evil/ByteBroom/releases/download/v1.0.0/ByteBroom_setup.exe",
        "https://github.com/SocheatSorng/ByteBroom/releases/download/v0.9.0/ByteBroom_setup.exe",
    ] {
        assert!(
            !node_accepts_at(&dir, &pubkey, &setup, &good, "1.0.0", url),
            "{url}"
        );
    }
    fs::remove_dir_all(&dir).unwrap();
}

/// Decode a Tauri signature, change its minisign lines, encode it again.
fn edit_signature(b64: &str, change: impl FnOnce(&mut Vec<String>)) -> String {
    let text = String::from_utf8(STANDARD.decode(b64).unwrap()).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    change(&mut lines);
    STANDARD.encode(lines.join("\n") + "\n")
}

/// Phase 6, decision 7: one version, set once in the workspace `Cargo.toml`. Tauri takes it from
/// there (no `version` in tauri.conf.json), and the README's status line states the same number.
#[test]
fn the_version_is_set_in_one_place_and_the_readme_agrees() {
    let conf: serde_json::Value = serde_json::from_str(&read("src-tauri/tauri.conf.json")).unwrap();
    assert!(
        conf.get("version").is_none(),
        "no second version in tauri.conf.json"
    );
    let cargo = read("Cargo.toml");
    let version = cargo
        .lines()
        .find_map(|l| l.strip_prefix("version = \""))
        .and_then(|v| v.strip_suffix('"'))
        .expect("workspace version");
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
    let status = read("README.md")
        .lines()
        .find(|l| l.starts_with("> **Status:"))
        .expect("README status line")
        .to_string();
    assert!(status.contains(&format!("version {version}")), "{status}");
}
