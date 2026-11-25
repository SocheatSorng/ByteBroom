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
        "docs/phase2-plan.md",
        "docs/phase3-plan.md",
        "docs/phase4-plan.md",
        "docs/recovery.md",
        "crates/scan/Cargo.toml",
        "build.ps1",
        "src-tauri/Cargo.toml",
        "src-tauri/tests/boundary.rs",
        "tools/ui-harness/serve.mjs",
        ".claude/agents/bytebroom-ui-designer.md",
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

/// Phase 3: the window's commands and the promises the README makes about it are in the code.
#[test]
fn the_window_commands_and_promises_match_the_code() {
    let readme = read("README.md");
    let claude = read("CLAUDE.md");
    let build = read("build.ps1");
    for command in [
        "cargo install --locked tauri-cli",
        "cargo tauri dev",
        "./build.ps1",
        "node tools/ui-harness/serve.mjs",
    ] {
        assert!(
            readme.contains(&format!("`{command}`")),
            "README lacks {command}"
        );
    }
    for command in [
        "cargo tauri dev",
        "./build.ps1",
        "node tools/ui-harness/serve.mjs",
    ] {
        assert!(claude.contains(command), "CLAUDE.md lacks {command}");
    }
    assert!(build.contains("cargo tauri build --no-bundle"));
    assert!(build.contains("cargo install --locked tauri-cli"));
    assert!(readme.contains("`target\\release\\bytebroom.exe`"));
    assert!(read("src-tauri/Cargo.toml").contains("name = \"bytebroom\""));

    // Default actions (owner's decision 1) as the README states them.
    let app = read("ui/app.js");
    assert!(app.contains(r#"defaultAction = (f) => (f.tier === "green" ? "Delete" : "Recycle")"#));
    assert!(readme.contains("Green items start ticked with \"Delete for good\""));
    assert!(readme.contains("start with \"Recycle Bin\""));
    for label in ["Delete for good", "Recycle Bin", "Move to folder"] {
        assert!(
            app.contains(&format!("\"{label}\"")),
            "app.js lacks {label}"
        );
        assert!(
            readme.contains(&format!("**{label}**")),
            "README lacks {label}"
        );
    }

    // The move journal and the log are where the README says.
    let lib = read("src-tauri/src/lib.rs");
    let relocate = read("crates/core/src/relocate.rs");
    let confirm = read("src-tauri/src/confirm.rs");
    assert!(readme.contains("`ByteBroom\\moves.journal`"));
    assert!(relocate.contains("open_or_create_dir(\"ByteBroom\")"));
    // Phase 5: the journals' names live in the history module, which the window uses.
    let history = read("crates/core/src/history.rs");
    assert!(history.contains("[\"moves.journal\", RecycledJournal::NAME]"));
    assert!(history.contains("NAME: &'static str = \"recycled.journal\""));
    assert!(read("src-tauri/src/history_cmd.rs").contains("HISTORY_FILES[0]"));
    assert!(lib.contains("history_cmd::open_journal(&dir)"));
    assert!(readme.contains("`ByteBroom\\recycled.journal`"));
    assert!(readme.contains("`ByteBroom\\bytebroom.log`"));
    assert!(confirm.contains("\"bytebroom.log\""));

    // The Recycle Bin warning, in the README and in the preview.
    assert!(readme.contains("recycling frees nothing by itself"));
    assert!(app.contains("That space comes back only when you empty the bin"));

    // Phase 5: the History view's buttons and promises, as the README names them.
    let page = read("ui/index.html");
    assert!(page.contains(">History…</button>") && readme.contains("**History…**"));
    assert!(page.contains(">Clear history…</button>") && readme.contains("**Clear history…**"));
    for (label, readme_label) in [
        ("\"Put back…\"", "**Put back…**"),
        ("`Put back all ${g.canPutBack}…`", "**Put back all…**"),
        ("\"Open the Recycle Bin\"", "**Open the Recycle Bin**"),
    ] {
        assert!(app.contains(label), "app.js lacks {label}");
        assert!(readme.contains(readme_label), "README lacks {readme_label}");
    }
    // Decision 3: ByteBroom never restores recycled items; decision 4: the page asks, Rust
    // checks the hash before removing the moved copy; rule S3: never elevated.
    assert!(readme.contains("ByteBroom never restores them itself"));
    assert!(readme.contains("removed only after the copy matches"));
    assert!(readme.contains("Putting back never runs as administrator."));
    assert!(relocate.contains("copy is deleted only after the restored file matched"));
    assert!(app.contains("the moved copy is removed only after the copy matches"));
}

#[test]
fn the_scan_tool_the_readme_names_exists() {
    let readme = read("README.md");
    assert!(readme.contains("`cargo run --release -p bytebroom-scan`"));
    let manifest = read("crates/scan/Cargo.toml");
    assert!(manifest.contains("name = \"bytebroom-scan\""));
    let workspace = read("Cargo.toml");
    assert!(workspace.contains("\"crates/scan\""));
    // CLAUDE.md names the same commands.
    let claude = read("CLAUDE.md");
    for command in [
        "./check.ps1",
        "cargo run --release -p bytebroom-scan",
        "cargo test --release -p bytebroom-core --test speed -- --ignored --nocapture",
    ] {
        assert!(claude.contains(command), "CLAUDE.md lacks {command}");
    }
    let speed = read("crates/core/tests/speed.rs");
    assert!(
        speed.contains(
            "cargo test --release -p bytebroom-core --test speed -- --ignored --nocapture"
        )
    );
}

/// Phase 4, task 3: the recovery recipe covers every helper action, its undo commands match
/// the owner's decisions, and the files and messages it names exist.
#[test]
fn the_recovery_recipe_matches_the_helper_and_the_plan() {
    use bytebroom_core::admin::AdminAction;
    let recipe = read("docs/recovery.md");
    let plan = read("docs/phase4-plan.md");
    for action in AdminAction::ALL {
        if action == AdminAction::Noop {
            continue;
        }
        assert!(
            recipe.contains(&format!("(`{}`)", action.arg())),
            "docs/recovery.md lacks the {action:?} action"
        );
    }
    // The undo command is the one decision 4 names.
    assert!(recipe.contains("`powercfg /hibernate on`"));
    assert!(plan.contains("Undo: `powercfg /hibernate on`"));
    // The helper's own words and files.
    assert!(recipe.contains("\"ByteBroom: restore point on request\""));
    assert!(read("crates/core/src/admin.rs").contains("\"ByteBroom: restore point on request\""));
    assert!(recipe.contains("`./tools/uninstall-helper.ps1`"));
    assert!(repo_root().join("tools/uninstall-helper.ps1").exists());
    assert!(recipe.contains(r"`Program Files\ByteBroom`"));
    // Every red action the owner chose has a row (decision 3).
    for row in [
        "| Hibernation off (`hibernation-off`) |",
        "| Delivery Optimization cache (`delivery-optimization-cache`) |",
        "| Empty the Recycle Bin |",
    ] {
        assert!(recipe.contains(row), "docs/recovery.md lacks {row}");
    }
    // The recipe never tells the owner to delete restore points or reset the component store.
    assert!(!recipe.contains("vssadmin delete"));
    assert!(!recipe.contains("/ResetBase /"));
}

/// Phase 4, task 7: the README's red-tier table matches the actions' words, texts and plans.
#[test]
fn the_readme_red_tier_matches_the_code() {
    use bytebroom_core::admin::{AdminAction, plan};
    use bytebroom_core::red_actions::RedAction;
    let readme = read("README.md");
    for a in RedAction::ALL {
        assert!(
            readme.contains(&format!("**{}**", a.title())),
            "{a:?} title"
        );
        assert!(
            readme.contains(&format!("`{}`", a.confirm_word())),
            "{a:?} word"
        );
    }
    // The commands the README names are the ones the helper runs.
    let s32 = r"C:\Windows\System32";
    let hib = plan(AdminAction::HibernationOff, s32)
        .unwrap()
        .args
        .join(" ");
    assert!(readme.contains(&format!("`powercfg {hib}`")));
    let cache = plan(AdminAction::DeliveryOptimizationCache, s32)
        .unwrap()
        .args
        .join(" ");
    assert!(cache.contains("Delete-DeliveryOptimizationCache -Force"));
    assert!(readme.contains("`Delete-DeliveryOptimizationCache -Force`"));
    assert!(readme.contains("`powercfg /hibernate on`"));
    // The Recycle Bin dialog's title and button, as the window shows them.
    let confirm = read("src-tauri/src/confirm.rs");
    assert!(readme.contains("\"ByteBroom: empty the Recycle Bin?\""));
    assert!(confirm.contains("EMPTY_TITLE: &str = \"ByteBroom: empty the Recycle Bin?\""));
    assert!(readme.contains("**Empty it**"));
    assert!(readme.contains("`docs/recovery.md`"));
}

/// Phase 4: the elevated helper the README describes is built, installed and removed by the
/// files it names, from the folder it names.
#[test]
fn the_helper_the_readme_names_is_built_and_installed_as_it_says() {
    let readme = read("README.md");
    for text in [
        r"`target\release\bytebroom-admin.exe`",
        r"`Program Files\ByteBroom`",
        "`./tools/install-helper.ps1`",
        "`./tools/uninstall-helper.ps1`",
    ] {
        assert!(readme.contains(text), "README lacks {text}");
    }
    assert!(read("build.ps1").contains("cargo build --release -p bytebroom-admin"));
    assert!(read("Cargo.toml").contains("\"crates/admin\""));
    let install = read("tools/install-helper.ps1");
    let uninstall = read("tools/uninstall-helper.ps1");
    for script in [&install, &uninstall] {
        assert!(script.starts_with("#Requires -RunAsAdministrator"));
        assert!(script.contains("Join-Path $programFiles 'ByteBroom'"));
        assert!(script.contains("'bytebroom-admin.exe'"));
    }
    let win = read("crates/core/src/win/admin.rs");
    assert!(win.contains("HELPER_FOLDER: &str = \"ByteBroom\""));
    assert!(win.contains("HELPER_EXE: &str = \"bytebroom-admin.exe\""));
}
