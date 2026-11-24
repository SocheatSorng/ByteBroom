//! Docs-drift test: the commands, files and versions that the README and CLAUDE.md promise must
//! exist in the code, `check.ps1` and CI.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/core sits two levels below the repo root")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The `cargo ...` lines inside the README's fenced command blocks.
fn readme_cargo_commands() -> Vec<String> {
    let readme = read("README.md");
    let mut in_block = false;
    let mut commands = Vec::new();
    for line in readme.lines() {
        if line.trim_start().starts_with("```") {
            in_block = !in_block;
            continue;
        }
        if in_block && line.trim_start().starts_with("cargo ") {
            commands.push(line.trim().to_string());
        }
    }
    commands
}

#[test]
fn readme_lists_the_four_checks() {
    let commands = readme_cargo_commands();
    assert_eq!(
        commands.len(),
        4,
        "README command block changed: {commands:?}"
    );
}

#[test]
fn every_readme_command_is_run_by_check_ps1() {
    let script = read("check.ps1");
    for command in readme_cargo_commands() {
        assert!(
            script.contains(&command),
            "check.ps1 does not run `{command}`"
        );
    }
}

#[test]
fn every_readme_command_is_run_by_ci() {
    let ci = read(".github/workflows/ci.yml") + &read(".github/workflows/security.yml");
    for command in readme_cargo_commands() {
        assert!(ci.contains(&command), "CI does not run `{command}`");
    }
}

#[test]
fn files_named_in_the_docs_exist() {
    for rel in [
        "check.ps1",
        "rust-toolchain.toml",
        "deny.toml",
        "LICENSE",
        "docs/spec.md",
        "docs/intent/bytebroom.md",
        "docs/phase1-plan.md",
    ] {
        assert!(
            repo_root().join(rel).exists(),
            "{rel} is named in the docs but missing"
        );
    }
}

#[test]
fn pinned_rust_version_matches_the_workspace() {
    let toolchain = read("rust-toolchain.toml");
    let cargo = read("Cargo.toml");
    let channel = toolchain
        .lines()
        .find_map(|l| l.strip_prefix("channel = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("rust-toolchain.toml has a channel line");
    let minor = channel
        .rsplit_once('.')
        .map(|(major_minor, _)| major_minor)
        .unwrap();
    assert!(
        cargo.contains(&format!("rust-version = \"{minor}\"")),
        "Cargo.toml rust-version does not match the pinned toolchain {channel}"
    );
}
