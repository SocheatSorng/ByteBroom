//! ByteBroom's safety core.
//!
//! Everything that decides what may be deleted lives here, apart from any UI. Decisions are pure
//! functions tested on fake data; Windows calls are kept in thin adapters (`win`, added in phase 1).

pub mod paths;
pub mod policy;

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
