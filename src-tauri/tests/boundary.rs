//! The boundary between the page and Rust, pinned: the command list, what each command accepts,
//! the capability file, the content security policy, the page's files and the app's dependencies.
//! A change to any of them must change these tests on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// Every command the window may call. Adding one is a security decision: update this list, the
/// capability file and `build.rs` together, and have the change reviewed.
const COMMANDS: [&str; 14] = [
    "start_scan",
    "cancel_scan",
    "scan_state",
    "preview",
    "clean",
    "pick_move_destination",
    "open_recycle_bin",
    "red_actions",
    "run_red_action",
    "history",
    "put_back",
    "clear_history",
    "update_check",
    "install_update",
];

/// The only parameter types a command may take: IDs and fixed choices (see `boundary.rs`), or
/// things Tauri itself provides (never sent by the page).
const PARAM_TYPES: [&str; 7] = [
    "Vec<Choice>",
    "PreviewId",
    "boundary::RedActionId",
    "boundary::PutBackId",
    "u32",
    "AppHandle",
    "State<",
];
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
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        // The history commands live in `history_cmd` (phase 5), the update ones in `update`
        // (phase 6); both are registered by path.
        .map(|s| {
            s.strip_prefix("history_cmd::")
                .or_else(|| s.strip_prefix("update::"))
                .unwrap_or(s)
                .to_string()
        })
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
fn the_app_loads_its_own_files_and_configures_only_the_updater() {
    let conf = json("tauri.conf.json");
    assert_eq!(conf["build"]["frontendDist"], "../ui");
    assert!(conf["build"].get("devUrl").is_none(), "no dev server");
    let plugins: Vec<&String> = conf["plugins"].as_object().unwrap().keys().collect();
    assert_eq!(plugins, vec!["updater"], "only the updater is configured");
    assert_eq!(
        conf["app"]["windows"],
        serde_json::json!([]),
        "the window is built in lib.rs, with navigation locked"
    );
}

/// Phase 6, decision 2: updates come only from this repo's GitHub Releases, over https, signed by
/// the owner's key, with the signed version checked. Changing any of this is a security decision.
#[test]
fn updates_come_only_from_this_repos_releases_signed_by_the_owners_key() {
    let conf = json("tauri.conf.json");
    let updater = conf["plugins"]["updater"].as_object().unwrap();
    let mut keys: Vec<&str> = updater.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        ["endpoints", "pubkey", "requireSignedVersion", "windows"],
        "no `dangerous*` switch or anything else"
    );
    assert_eq!(
        updater["endpoints"],
        serde_json::json!([
            "https://github.com/SocheatSorng/ByteBroom/releases/latest/download/latest.json"
        ])
    );
    assert_eq!(updater["requireSignedVersion"], true);
    assert_eq!(
        updater["windows"],
        serde_json::json!({"installMode": "passive"})
    );
    // The public key: a base64-encoded minisign public key file, never a path or a secret key.
    let pubkey = updater["pubkey"].as_str().unwrap();
    let decoded = decode_base64(pubkey);
    assert!(
        decoded.starts_with("untrusted comment: minisign public key: "),
        "pubkey is a minisign public key"
    );
    assert!(!decoded.to_lowercase().contains("secret"));
}

/// A minimal standard-base64 decoder, so this test needs no extra crate.
fn decode_base64(text: &str) -> String {
    const ABC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in text.bytes().filter(|&c| c != b'=') {
        let v = ABC.iter().position(|&a| a == c).expect("base64") as u32;
        bits = (bits << 6) | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
            bits &= (1 << n) - 1;
        }
    }
    String::from_utf8(out).expect("utf-8")
}

/// No private signing key, or anything that looks like one, is ever committed.
#[test]
fn no_private_key_is_in_the_repo() {
    let root = crate_dir().join("..");
    let out = std::process::Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(&root)
        .output()
        .expect("git ls-files");
    let markers = [
        "PRIVATE KEY-----",
        "minisign encrypted secret key",
        "minisign secret key",
        // Tauri's key file: base64 of "untrusted comment: rsign encrypted secret key", that
        // header decoded, and the decoded key line ("EdScB2": an encrypted minisign secret key).
        "dW50cnVzdGVkIGNvbW1lbnQ6IHJzaWduIGVuY3J5cHRlZCBzZWNyZXQga2V5",
        "rsign encrypted secret key",
        "RWRTY0Iy",
    ];
    for name in String::from_utf8(out.stdout).unwrap().split('\0') {
        if name.is_empty() || name == "src-tauri/tests/boundary.rs" {
            continue;
        }
        let bytes = fs::read(root.join(name)).unwrap_or_default();
        // As UTF-8 (or Latin-1 for binaries), and as UTF-16 (PowerShell 5.1's default output),
        // so a key pasted into any text file is found (security review N1).
        let utf16 = |from: usize| {
            let units: Vec<u16> = bytes[from.min(bytes.len())..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| u16::from_le_bytes(c))
                .collect();
            String::from_utf16_lossy(&units)
        };
        let texts = [
            bytes.iter().map(|&b| b as char).collect::<String>(),
            utf16(0),
            utf16(1),
        ];
        for text in &texts {
            for marker in markers {
                assert!(!text.contains(marker), "{name} holds a private-key marker");
            }
        }
        let lower = name.to_lowercase();
        assert!(
            !lower.ends_with(".key") && !lower.contains("signing"),
            "{name} looks like a key file"
        );
    }
}

/// Security review S2: the updater runs exactly as `tauri.conf.json` says. No code may swap its
/// key, endpoint, version rule or installer arguments, which the tests above can't see.
#[test]
fn no_code_overrides_the_updaters_configuration() {
    let lib = read("src/lib.rs");
    assert_eq!(
        lib.matches("tauri_plugin_updater::Builder::new().build()")
            .count(),
        1,
        "the plugin is set up once, with nothing between new() and build()"
    );
    for file in files_under(&crate_dir().join("src")) {
        let text = fs::read_to_string(&file).unwrap();
        for never in [
            "version_comparator",
            "updater_builder",
            ".pubkey(",
            ".endpoints(",
            "installer_arg",
            "dangerous",
            "restart_after_install",
            "on_before_exit",
            "executable_path",
            ".target(",
            ".header(",
            ".proxy(",
            "configure_client",
        ] {
            assert!(!text.contains(never), "{} uses {never}", file.display());
        }
    }
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
    // Phase 3, decision 4: tauri and the dialog plugin (Rust side only). Phase 6, decision 2: the
    // updater plugin, driven from Rust only (no `updater:` permission; see the capability test).
    let approved = [
        "bytebroom-core",
        "serde",
        "serde_json",
        "tauri",
        "tauri-plugin-dialog",
        "tauri-plugin-updater",
    ];
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

/// Security review: the page's confirmations can be skipped by a page, so `clean` itself asks in
/// Windows' own dialog before touching amber items, and only then starts acting.
#[test]
fn clean_asks_in_rust_before_acting_on_amber_items() {
    let lib = read("src/lib.rs");
    let body = lib
        .split("async fn clean(")
        .nth(1)
        .and_then(|s| s.split("\n}\n").next())
        .expect("the clean command");
    // The gate itself (every verdict but Clean stops, for a move and a recycle alike) is tested
    // in lib.rs, `only_clean_them_lets_an_amber_move_or_recycle_through`.
    let ask = body
        .find("amber_refusal(&asking")
        .expect("clean asks through the gate");
    let shown = body.find("confirm::ask(").expect("in a native dialog");
    let stop = body
        .find("if let Some(why) = stop")
        .expect("anything but a clean verdict stops the clean");
    assert!(
        body.contains(".unwrap_or_else(|_| confirm::refusal(confirm::Verdict::Unavailable))"),
        "a dialog thread that fails stops the clean"
    );
    let act = body.find("carry_out(").expect("clean acts");
    assert!(
        ask < shown && shown < stop && stop < act,
        "the question comes before acting"
    );
    // Phase 3's open bug and review S1: ByteBroom's own task dialog, owned by the main window,
    // every answer logged; the plugin's message dialog, whose default button confirms, is not
    // used for this question.
    let confirm = read("src/confirm.rs");
    assert!(confirm.contains("get_webview_window(\"main\")") && confirm.contains(".hwnd()"));
    assert!(confirm.contains("taskdialog::ask("));
    assert!(
        !confirm.contains(".message("),
        "not the plugin's message dialog"
    );
    assert!(confirm.contains("log("), "every answer is logged");
    let td = read("../crates/core/src/win/taskdialog.rs");
    assert!(
        td.contains("nDefaultButton: IDCANCEL"),
        "Cancel is the default button"
    );
    assert!(
        td.contains("TDN_CREATED"),
        "the clock starts when the dialog exists"
    );
}

/// Owner's real test: the browser's own menu (Back, Refresh, Print) and reload keys wiped the
/// window's list mid-task. The page blocks them.
#[test]
fn the_window_has_no_browser_menu_or_reload_keys() {
    let app = fs::read_to_string(crate_dir().join("..").join("ui").join("app.js")).unwrap();
    assert!(app.contains("addEventListener(\"contextmenu\""));
    for key in ["\"f5\"", "\"r\"", "\"p\"", "\"arrowleft\""] {
        assert!(app.contains(key), "app.js does not block {key}");
    }
}

/// The UI harness (tools/ui-harness) fakes the commands in a browser; none of it may reach the
/// app. The app has no Cargo features at all, so no build can switch fake data on, and the
/// window's files never name the harness.
#[test]
fn the_app_has_no_fake_data_and_the_page_never_loads_the_harness() {
    let manifest = read("Cargo.toml");
    assert!(
        !manifest.contains("[features]"),
        "the app has no Cargo features"
    );
    for file in files_under(&crate_dir().join("src")) {
        let text = fs::read_to_string(&file).unwrap();
        assert!(!text.contains("cfg(feature"), "{}", file.display());
        assert!(!text.to_lowercase().contains("mock"), "{}", file.display());
    }
    for file in files_under(&crate_dir().join("..").join("ui")) {
        if let Ok(text) = fs::read_to_string(&file) {
            for bad in ["__harness", "mock-tauri", "ui-harness"] {
                assert!(!text.contains(bad), "{} names {bad}", file.display());
            }
        }
    }
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
                "insertadjacenthtml",
                "createcontextualfragment",
                "document.write",
            ] {
                assert!(!lower.contains(bad), "{name} uses {bad}");
            }
        }
    }
}

/// Phase 4: the page's typed confirm can be skipped by a page, so `run_red_action` asks
/// natively first: Windows' own dialog before emptying the Recycle Bin, and the UAC prompt (the
/// helper) for the rest. The page sends only a fixed choice.
#[test]
fn red_actions_ask_natively_before_acting() {
    let lib = read("src/lib.rs");
    let body = lib
        .split("async fn run_red_action(")
        .nth(1)
        .and_then(|s| s.split("\n}\n").next())
        .expect("run_red_action");
    let ask = body
        .find("ask_empty_recycle_bin")
        .expect("asks before emptying");
    let refusal = body
        .find("confirm::empty_refusal(verdict)")
        .expect("acts on the answer");
    let empty = body
        .find("empty_recycle_bin(parent)")
        .expect("empties the bin");
    assert!(
        ask < refusal && refusal < empty,
        "the dialog comes before emptying"
    );
    assert!(body.contains("run_elevated(admin, parent)"));
    // The emptying function is called nowhere else in the app.
    assert_eq!(lib.matches("recycle::empty_recycle_bin(").count(), 1);
    let confirm = read("src/confirm.rs");
    assert!(confirm.contains("pub const EMPTY_IT: &str = \"Empty it\";"));
    // The page sends a fixed enum, whose variants match the core's actions.
    let boundary = read("src/boundary.rs");
    for v in ["RecycleBin", "DeliveryOptimization", "Hibernation"] {
        assert!(boundary.contains(&format!("    {v},")), "{v}");
    }
}

/// Security review, phase 5, S1: the journals are user-writable, so putting back and clearing
/// refuse to run with an administrator token, before touching any journal, and pass Windows'
/// own answer on to the core, which refuses too.
#[test]
fn put_back_and_clear_history_refuse_to_run_elevated() {
    let cmds = read("src/history_cmd.rs");
    assert!(cmds.contains("bytebroom_core::win::admin::is_elevated()"));
    for (command, acts) in [
        ("pub async fn put_back(", "undo_entries("),
        ("pub async fn clear_history(", "history::clear_history("),
    ] {
        let body = cmds
            .split(command)
            .nth(1)
            .and_then(|s| s.split("#[tauri::command]").next())
            .unwrap_or_else(|| panic!("{command} in history_cmd.rs"));
        let gate = body
            .find("refuse_if_elevated(elevated())?")
            .unwrap_or_else(|| panic!("{command} does not refuse when elevated"));
        let lock = body.find("history.lock()").expect("takes the history lock");
        let act = body.find(acts).expect("acts");
        assert!(
            gate < lock && gate < act,
            "{command}: the gate must come first"
        );
        // The core gets Windows' answer, not a constant.
        assert!(
            body[act..]
                .trim_start_matches(acts)
                .trim_start()
                .starts_with("elevated()"),
            "{command} passes elevated() to the core"
        );
    }
}
