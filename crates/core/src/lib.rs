//! ByteBroom's safety core.
//!
//! Everything that decides what may be deleted lives here, apart from any UI. Decisions are pure
//! functions tested on fake data; Windows calls are kept in the thin `win` adapter, the only
//! module allowed to use `unsafe`.

pub mod clean;
pub mod duplicates;
pub mod engine;
pub mod locations;
pub mod paths;
pub mod policy;
pub mod recycle;
pub mod red;
pub mod relocate;
pub mod rules;
pub mod scan;
pub mod summary;
pub mod walk;
pub mod win;

/// The version of this crate, shown in the app and checked by the docs-drift test.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_semver() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "version {VERSION} is not x.y.z");
        assert!(parts.iter().all(|p| p.parse::<u32>().is_ok()));
    }
}
