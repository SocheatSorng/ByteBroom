//! Harness for phase 3's open bug: shows the real amber dialog (`confirm::ask`) over the real
//! window, with a made-up question, and nothing else. No command is registered, so the page can
//! do nothing; no file is touched. The answer is logged in the folder given as the only argument
//! (a scratch folder, never the owner's local app data) and the verdict is written to stderr.
//!
//! Run: `cargo run -p bytebroom-app --example amber_dialog -- <scratch folder>`
#![allow(clippy::print_stderr)]

use bytebroom_app::confirm;
use bytebroom_core::paths::WinPath;
use tauri::{WebviewUrl, WebviewWindowBuilder};

fn main() -> tauri::Result<()> {
    let base = std::env::args()
        .nth(1)
        .and_then(|a| WinPath::parse(&a).ok());
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("ByteBroom dialog harness")
                .inner_size(1100.0, 760.0)
                .build()?;
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let question = "1 of your own file (66.5 MB) will be cleaned as the preview \
                                showed:\n\n- 1 sent to the Recycle Bin\n\nD:\\Example\\setup.exe\n"
                    .to_string();
                let v = confirm::ask(&handle, &question, 1, base.as_ref());
                eprintln!("verdict: {v:?}");
                handle.exit(0);
            });
            Ok(())
        })
        .run(tauri::generate_context!())
}
