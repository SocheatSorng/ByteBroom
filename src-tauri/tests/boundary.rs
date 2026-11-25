//! The boundary between the page and Rust, pinned: the command list, what each command accepts,
//! the capability file, the content security policy, the page's files and the app's dependencies.
//! A change to any of them must change these tests on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// Every command the window may call. Adding one is a security decision: update this list, the
/// capability file and `build.rs` together, and have the change reviewed.
const COMMANDS: [&str; 7] = [
    "start_scan",
    "cancel_scan",
    "scan_state",
    "preview",
    "clean",
    "pick_move_destination",
    "open_recycle_bin",
];

/// The only parameter types a command may take: IDs and fixed choices (see `boundary.rs`), or
/// things Tauri itself provides (never sent by the page).
const PARAM_TYPES: [&str; 5] = ["Vec<Choice>", "PreviewId", "u32", "AppHandle", "State<"];
// `State<` is matched as a prefix: Tauri fills it from the app, never from the page.

/// Type names that could carry text or a path from the page.
const TEXT_OR_PATH_TYPES: [&str; 11] = [
    "String", "str", "char", "Path", "PathBuf", "OsStr", "OsString", "Value", "Cow", "Vec<u8>",
    "Box<dyn",
];

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    fs::read_to_string(crate_dir().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn json(rel: &str) -> Value {
    serde_json::from_str(&read(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// `(name, parameter list)` of every `#[tauri::command]` function in `src/`.
fn commands_in_source() -> Vec<(String, String)> {
    let mut found = Vec::new();
    for file in files_under(&crate_dir().join("src")) {
        let text = fs::read_to_string(&file).unwrap();
        for chunk in text.split("#[tauri::command]").skip(1) {
            let sig = chunk.split('{').next().unwrap();
            let after_fn = sig.split("fn ").nth(1).expect("a command is a function");
            let name = after_fn.split('(').next().unwrap().trim().to_string();
            // The parameter list runs to the `)` that closes the first `(`.
            let open = after_fn.split_once('(').unwrap().1;
            let mut depth = 1;
            let end = open
                .char_indices()
                .find(|&(_, c)| {
                    match c {
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        _ => {}
                    }
                    depth == 0
                })
                .map(|(i, _)| i)
                .expect("a closed parameter list");
            found.push((name, open[..end].to_string()));
        }
    }
    found.sort();
    found
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else {
            out.push(path);
        }
    }
    out.sort();
    out
}

fn sorted(list: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = list.iter().map(|s| s.to_string()).collect();
    v.sort();
    v
}

#[test]
fn every_command_is_on_the_list_and_registered() {
    let in_source: Vec<String> = commands_in_source().into_iter().map(|(n, _)| n).collect();
    assert_eq!(in_source, sorted(&COMMANDS));

    // The handler registers exactly these.
    let lib = read("src/lib.rs");
    let handler = lib
        .split("generate_handler![")
        .nth(1)
        .and_then(|s| s.split(']').next())
        .expect("one generate_handler! in lib.rs");
    let mut registered: Vec<String> = handler
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    registered.sort();
    assert_eq!(registered, sorted(&COMMANDS));
    assert_eq!(lib.matches("generate_handler!").count(), 1);

    // build.rs generates a permission for each, and only these.
    let build = read("build.rs");
    let listed = build
        .split("const COMMANDS: &[&str] = &[")
        .nth(1)
        .and_then(|s| s.split("];").next())
        .expect("COMMANDS in build.rs");
    let mut from_build: Vec<String> = listed
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    from_build.sort();
    assert_eq!(from_build, sorted(&COMMANDS));
}

#[test]
fn no_command_takes_text_or_a_path() {
    for (name, params) in commands_in_source() {
        for param in split_top_level(&params) {
            let ty = param
                .split_once(':')
                .map(|(_, t)| t.trim())
                .unwrap_or_else(|| panic!("{name}: {param}"));
            // Tauri's own injected values match by prefix; what the page sends must match exactly.
            assert!(
                PARAM_TYPES
                    .iter()
                    .any(|ok| ty == *ok || (ok.ends_with('<') && ty.starts_with(ok))),
                "{name} takes `{ty}`, which is not on the allow-list"
            );
        }
    }
}

/// Split a parameter list at the commas that are not inside `<...>`.
fn split_top_level(params: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut depth = 0;
    for c in params.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            ',' if depth == 0 => {
                out.push(String::new());
                continue;
            }
            _ => {}
        }
        out.last_mut().unwrap().push(c);
    }
    out.into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

#[test]
fn the_parameter_check_catches_text_and_paths() {
    // The check above, on made-up signatures: these must all be refused.
    let allowed = |ty: &str| {
        PARAM_TYPES
            .iter()
            .any(|ok| ty == *ok || (ok.ends_with('<') && ty.starts_with(ok)))
    };
    for bad in [
        "String",
        "&str",
        "PathBuf",
        "Vec<String>",
        "u32x",
        "Vec<Choice>x",
    ] {
        assert!(!allowed(bad), "{bad}");
    }
    assert_eq!(
        split_top_level("s: State<'_, Arc<Session>>, seen: u32"),
        vec!["s: State<'_, Arc<Session>>", "seen: u32"]
    );
}

#[test]
fn what_the_page_sends_holds_no_text_or_path_types() {
    let boundary = read("src/boundary.rs");
    let code: String = boundary
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for word in code.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '<')) {
        for bad in TEXT_OR_PATH_TYPES {
            if !bad.contains('<') && !bad.contains(' ') {
                assert_ne!(word, bad, "boundary.rs uses `{bad}`");
            }
        }
    }
    for bad in ["Vec<u8>", "Box<dyn", "serde_json", "&'"] {
        assert!(!code.contains(bad), "boundary.rs uses `{bad}`");
    }
    // Every struct refuses fields the page made up.
    let structs = code.matches("pub struct").count();
    let strict = code.matches("#[serde(deny_unknown_fields)]").count();
    assert_eq!(structs, strict);
}

#[test]
fn the_capability_grants_only_these_commands_to_the_main_window() {
    let dir = crate_dir().join("capabilities");
    let files = files_under(&dir);
    assert_eq!(files, vec![dir.join("main.json")], "one capability file");
    let cap = json("capabilities/main.json");
    let keys: Vec<&String> = cap.as_object().unwrap().keys().collect();
    for key in &keys {
        assert!(
            ["identifier", "description", "windows", "permissions"].contains(&key.as_str()),
            "unexpected capability key {key} (no `remote`, `webviews` or `platforms`)"
        );
    }
    assert_eq!(cap["windows"], serde_json::json!(["main"]));
    let mut granted: Vec<String> = cap["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().expect("plain permission names only").to_string())
        .collect();
    granted.sort();
    let mut expected: Vec<String> = COMMANDS
        .iter()
        .map(|c| format!("allow-{}", c.replace('_', "-")))
        .collect();
    expected.sort();
    assert_eq!(granted, expected);
}

#[test]
fn the_csp_forbids_remote_and_inline_code() {
    let conf = json("tauri.conf.json");
    let security = &conf["app"]["security"];
    let csp = security["csp"].as_object().expect("a CSP is set");
    let allowed_sources = ["'self'", "'none'", "ipc:", "http://ipc.localhost"];
    for (directive, sources) in csp {
        for source in sources.as_str().unwrap().split_whitespace() {
            assert!(
                allowed_sources.contains(&source),
                "{directive} allows {source}"
            );
        }
    }
    for directive in ["default-src", "script-src", "style-src"] {
        assert_eq!(csp[directive], "'self'", "{directive}");
    }
    for directive in ["object-src", "base-uri", "form-action", "frame-src"] {
        assert_eq!(csp[directive], "'none'", "{directive}");
    }
    // Nothing that loosens it.
    for key in security.as_object().unwrap().keys() {
        assert!(!key.starts_with("dangerous"), "{key}");
    }
    assert_eq!(security["freezePrototype"], true);
    assert!(security.get("devCsp").is_none());
    assert!(security.get("assetProtocol").is_none());
}

#[test]
fn the_app_loads_its_own_files_and_no_plugins() {
    let conf = json("tauri.conf.json");
    assert_eq!(conf["build"]["frontendDist"], "../ui");
    assert!(conf["build"].get("devUrl").is_none(), "no dev server");
    assert!(conf.get("plugins").is_none(), "no plugin configuration");
    assert_eq!(
        conf["app"]["windows"],
        serde_json::json!([]),
        "the window is built in lib.rs, with navigation locked"
    );
}

#[test]
fn the_app_depends_only_on_approved_crates() {
    let manifest = read("Cargo.toml");
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .and_then(|s| s.split("\n[").next())
        .expect("[dependencies]");
    let mut names: Vec<&str> = deps
        .lines()
        .filter_map(|l| l.split_once('=').map(|(n, _)| n.trim()))
        .filter(|n| !n.is_empty())
        .collect();
    names.sort();
    // Owner's decision 4: tauri and the dialog plugin (Rust side only); no other plugins.
    let approved = ["bytebroom-core", "serde", "tauri", "tauri-plugin-dialog"];
    for name in &names {
        assert!(approved.contains(name), "unapproved dependency {name}");
    }
    let tauri_line = deps
        .lines()
        .find(|l| l.trim_start().starts_with("tauri ="))
        .expect("tauri");
    assert!(
        tauri_line.contains("features = []"),
        "no extra tauri features: {tauri_line}"
    );
}

#[test]
fn the_page_loads_nothing_remote_and_runs_no_inline_code() {
    let ui = crate_dir().join("..").join("ui");
    let files = files_under(&ui);
    assert!(!files.is_empty());
    for file in files {
        let name = file.display().to_string();
        let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
        assert!(
            ["html", "css", "js", "svg", "ico", "png"].contains(&ext),
            "{name}: unexpected file type"
        );
        if !["html", "css", "js", "svg"].contains(&ext) {
            continue;
        }
        let text = fs::read_to_string(&file).unwrap();
        let lower = text.to_ascii_lowercase();
        for bad in ["http://", "https://", "//cdn", "@import", "url(http"] {
            assert!(!lower.contains(bad), "{name} contains {bad}");
        }
        if ext == "html" {
            // Every <script> has a src and no body.
            for tag in lower.split("<script").skip(1) {
                let open = tag.split('>').next().unwrap();
                assert!(open.contains("src="), "{name}: inline script");
                assert!(
                    tag.split_once('>')
                        .unwrap()
                        .1
                        .trim_start()
                        .starts_with("</script"),
                    "{name}: script with a body"
                );
            }
            assert!(!lower.contains(" style="), "{name}: inline style");
            for attr in lower.split_whitespace() {
                assert!(
                    !(attr.starts_with("on") && attr.contains('=')),
                    "{name}: inline handler {attr}"
                );
            }
            assert!(!lower.contains("javascript:"), "{name}: javascript: URL");
        }
        if ext == "js" {
            for bad in [
                "eval(",
                "new function",
                "innerhtml",
                "outerhtml",
                "document.write",
            ] {
                assert!(!lower.contains(bad), "{name} uses {bad}");
            }
        }
    }
}
