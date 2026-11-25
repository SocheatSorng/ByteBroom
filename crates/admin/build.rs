//! Link the helper so Windows loads even its start-up DLLs (the C runtime, imported before
//! `main` runs) only from System32: `/DEPENDENTLOADFLAG:0x800` is LOAD_LIBRARY_SEARCH_SYSTEM32
//! for the program's own imports (security review of task 1, S3). `tests/pe.rs` reads the
//! built program's header to prove it is set.

fn main() {
    println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    println!("cargo:rerun-if-changed=build.rs");
}
