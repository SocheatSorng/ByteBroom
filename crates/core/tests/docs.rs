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

/// The `| Tier | Category |` rows of the README's "What ByteBroom cleans" section.
fn readme_categories() -> Vec<(String, String)> {
    let readme = read("README.md");
    let section = readme
        .split("## What ByteBroom cleans")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("README has a 'What ByteBroom cleans' section");
    section
        .lines()
        .filter_map(|line| {
            let cells: Vec<&str> = line.trim().trim_matches('|').split('|').collect();
            match cells.as_slice() {
                [tier, label] if ["Green", "Amber", "Red"].contains(&tier.trim()) => {
                    Some((tier.trim().to_string(), label.trim().to_string()))
                }
                _ => None,
            }
        })
        .collect()
}

#[test]
fn readme_category_list_matches_the_rules() {
    use bytebroom_core::rules::RULES;
    let from_code: Vec<(String, String)> = RULES
        .iter()
        .map(|r| (r.tier.name().to_string(), r.label.to_string()))
        .collect();
    assert_eq!(readme_categories(), from_code);
}

#[test]
fn readme_never_listed_names_match_the_rules() {
    use bytebroom_core::rules::{
        NEVER_LISTED_EXTENSIONS, NEVER_LISTED_FOLDERS, NEVER_LISTED_NAMES,
    };
    let readme = read("README.md").replace("\r\n", "\n");
    let paragraph = readme
        .split("Never listed at all")
        .nth(1)
        .and_then(|rest| rest.split("\n\n").next())
        .expect("README lists what is never listed");
    let quoted: Vec<&str> = paragraph.split('`').skip(1).step_by(2).collect();
    let mut from_code: Vec<String> = NEVER_LISTED_FOLDERS
        .iter()
        .chain(NEVER_LISTED_NAMES.iter())
        .map(|n| n.to_string())
        .chain(NEVER_LISTED_EXTENSIONS.iter().map(|e| format!(".{e}")))
        .collect();
    let mut from_readme: Vec<String> = quoted.iter().map(|q| q.to_string()).collect();
    from_code.sort();
    from_readme.sort();
    assert_eq!(from_readme, from_code);
}
