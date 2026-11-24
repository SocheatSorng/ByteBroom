//! Strict parsing of Windows paths.
//!
//! The delete engine only ever sees paths that Windows itself reported for an open handle
//! (`GetFinalPathNameByHandle`), so real paths are always absolute, long-named and canonical.
//! Anything that could make two different strings name the same file, or one string name a file
//! somewhere unexpected, is refused here instead of being "fixed": `.`/`..` parts, alternate data
//! streams, trailing dots or spaces, device and network paths, reserved names and wildcards.

use std::fmt;

/// Why a path string was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// Not of the form `X:\...` (relative, rooted without a drive, or empty).
    NotAbsolute,
    /// A network (UNC) path; V1 never acts on network drives.
    Network,
    /// A device or volume path such as `\\.\` or `\\?\GLOBALROOT`.
    Device,
    /// A `.` or `..` part, or an empty part (`a\\b`).
    Relative,
    /// A part that Windows would silently change or treat specially.
    BadComponent(String),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute => write!(f, "not an absolute drive path"),
            Self::Network => write!(f, "network paths are not supported"),
            Self::Device => write!(f, "device and volume paths are not supported"),
            Self::Relative => write!(f, "the path contains '.', '..' or an empty part"),
            Self::BadComponent(c) => write!(f, "the path part {c:?} is not allowed"),
        }
    }
}

impl std::error::Error for PathError {}

/// An absolute Windows path on a lettered drive, checked part by part.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WinPath {
    drive: char,
    parts: Vec<String>,
}

const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn check_component(part: &str) -> Result<(), PathError> {
    if part.is_empty() || part == "." || part == ".." {
        return Err(PathError::Relative);
    }
    let bad = || PathError::BadComponent(part.to_string());
    if part.ends_with('.') || part.ends_with(' ') {
        return Err(bad());
    }
    if part.chars().any(|c| {
        c.is_control() || matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|' | '/' | '\\')
    }) {
        return Err(bad());
    }
    // "NUL", "nul.txt", "COM1.log" all open the device, not a file.
    let stem = part.split('.').next().unwrap_or(part).trim_end();
    if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
        return Err(bad());
    }
    Ok(())
}

impl WinPath {
    /// Parse `C:\a\b`, `C:/a/b` or `\\?\C:\a\b`. Everything else is refused.
    pub fn parse(input: &str) -> Result<Self, PathError> {
        let unified = input.replace('/', "\\");
        let rest = if let Some(after) = unified.strip_prefix("\\\\?\\") {
            let upper = after.to_ascii_uppercase();
            if upper.starts_with("UNC\\") {
                return Err(PathError::Network);
            }
            if upper.starts_with("GLOBALROOT") || upper.starts_with("VOLUME{") {
                return Err(PathError::Device);
            }
            after.to_string()
        } else if unified.starts_with("\\\\.\\") || unified.starts_with("\\??\\") {
            return Err(PathError::Device);
        } else if unified.starts_with("\\\\") {
            return Err(PathError::Network);
        } else {
            unified
        };

        let mut chars = rest.chars();
        let drive = match (chars.next(), chars.next(), chars.next()) {
            (Some(d), Some(':'), Some('\\')) if d.is_ascii_alphabetic() => d.to_ascii_uppercase(),
            (Some(d), Some(':'), None) if d.is_ascii_alphabetic() => {
                // "C:" alone means "the current folder on C:", not the root.
                return Err(PathError::NotAbsolute);
            }
            _ => return Err(PathError::NotAbsolute),
        };
        let tail: String = chars.collect();
        let mut parts = Vec::new();
        if !tail.is_empty() {
            let tail = tail.strip_suffix('\\').unwrap_or(&tail);
            for part in tail.split('\\') {
                check_component(part)?;
                parts.push(part.to_string());
            }
        }
        Ok(Self { drive, parts })
    }

    /// `X:\` for a drive letter. A character that is not an ASCII letter gives `C:\`.
    pub fn drive_root(letter: char) -> Self {
        let drive = if letter.is_ascii_alphabetic() {
            letter.to_ascii_uppercase()
        } else {
            'C'
        };
        Self {
            drive,
            parts: Vec::new(),
        }
    }

    /// The drive letter, upper case.
    pub fn drive(&self) -> char {
        self.drive
    }

    /// The parts after the drive root, in order.
    pub fn parts(&self) -> &[String] {
        &self.parts
    }

    /// True for `X:\` itself.
    pub fn is_drive_root(&self) -> bool {
        self.parts.is_empty()
    }

    /// True when `self` lies below `root` (never when they are the same path). The comparison is
    /// exact, case included: both paths are expected to come from Windows, which reports the real
    /// on-disk names, so any mismatch can only cause a refusal.
    pub fn is_strictly_inside(&self, root: &WinPath) -> bool {
        self.drive == root.drive
            && self.parts.len() > root.parts.len()
            && self.parts.iter().zip(&root.parts).all(|(a, b)| a == b)
    }

    /// Like [`Self::is_strictly_inside`] or equal, but ignoring case. Used only for deny-list
    /// checks, where matching more paths can only refuse more.
    pub fn is_at_or_inside_ignore_case(&self, area: &WinPath) -> bool {
        self.drive == area.drive
            && self.parts.len() >= area.parts.len()
            && self
                .parts
                .iter()
                .zip(&area.parts)
                .all(|(a, b)| eq_ignore_case(a, b))
    }

    /// Same path, ignoring case.
    pub fn eq_ignore_case(&self, other: &WinPath) -> bool {
        self.parts.len() == other.parts.len() && self.is_at_or_inside_ignore_case(other)
    }

    /// A child path. Fails if `part` is not a single valid part.
    pub fn join(&self, part: &str) -> Result<Self, PathError> {
        check_component(part)?;
        let mut parts = self.parts.clone();
        parts.push(part.to_string());
        Ok(Self {
            drive: self.drive,
            parts,
        })
    }
}

/// Case-insensitive comparison close to NTFS's: one-to-one upper-casing, no expansions.
fn eq_ignore_case(a: &str, b: &str) -> bool {
    fn fold(c: char) -> char {
        let mut up = c.to_uppercase();
        match (up.next(), up.next()) {
            (Some(u), None) => u,
            _ => c,
        }
    }
    a.chars().count() == b.chars().count()
        && a.chars().zip(b.chars()).all(|(x, y)| fold(x) == fold(y))
}

impl fmt::Display for WinPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:\\{}", self.drive, self.parts.join("\\"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> WinPath {
        WinPath::parse(s).unwrap()
    }

    #[test]
    fn accepts_plain_and_verbatim_drive_paths() {
        assert_eq!(p("C:\\Temp\\a.txt"), p("\\\\?\\C:\\Temp\\a.txt"));
        assert_eq!(p("c:/Temp/a.txt"), p("C:\\Temp\\a.txt"));
        assert_eq!(p("C:\\Temp\\"), p("C:\\Temp"));
        assert!(p("D:\\").is_drive_root());
        assert_eq!(p("C:\\Temp\\a.txt").to_string(), "C:\\Temp\\a.txt");
    }

    #[test]
    fn refuses_paths_that_could_alias_or_escape() {
        let cases = [
            ("Temp\\a", PathError::NotAbsolute),
            ("\\Temp\\a", PathError::NotAbsolute),
            ("C:", PathError::NotAbsolute),
            ("C:Temp", PathError::NotAbsolute),
            ("", PathError::NotAbsolute),
            ("\\\\server\\share\\a", PathError::Network),
            ("\\\\?\\UNC\\server\\share", PathError::Network),
            ("\\\\.\\C:\\a", PathError::Device),
            ("\\\\.\\PhysicalDrive0", PathError::Device),
            ("\\??\\C:\\a", PathError::Device),
            (
                "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1",
                PathError::Device,
            ),
            (
                "\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\a",
                PathError::Device,
            ),
            ("C:\\Temp\\..\\Windows", PathError::Relative),
            ("C:\\Temp\\.\\a", PathError::Relative),
            ("C:\\Temp\\\\a", PathError::Relative),
        ];
        for (input, want) in cases {
            assert_eq!(WinPath::parse(input), Err(want), "{input}");
        }
        for input in [
            "C:\\Temp\\a.txt:hidden", // alternate data stream
            "C:\\Temp\\a.txt::$DATA", // default stream
            "C:\\Temp\\a.",           // trailing dot is dropped by Windows
            "C:\\Temp\\a ",           // trailing space is dropped by Windows
            "C:\\Temp\\NUL",          // device name
            "C:\\Temp\\com1.txt",     // device name with an extension
            "C:\\Temp\\*.tmp",        // wildcard
            "C:\\Temp\\a?b",          // wildcard
            "C:\\Temp\\a\u{0}b",      // control character
        ] {
            assert!(
                matches!(WinPath::parse(input), Err(PathError::BadComponent(_))),
                "{input} was accepted"
            );
        }
    }

    #[test]
    fn strictly_inside_is_exact_and_excludes_the_root_itself() {
        let root = p("C:\\Users\\Ann\\AppData\\Local\\Temp");
        assert!(p("C:\\Users\\Ann\\AppData\\Local\\Temp\\x").is_strictly_inside(&root));
        assert!(!root.is_strictly_inside(&root));
        assert!(!p("C:\\Users\\Ann\\AppData\\Local\\Temp2\\x").is_strictly_inside(&root));
        assert!(!p("C:\\Users\\Ann\\AppData\\Local\\TEMP\\x").is_strictly_inside(&root));
        assert!(!p("D:\\Users\\Ann\\AppData\\Local\\Temp\\x").is_strictly_inside(&root));
        assert!(!p("C:\\Users\\Ann").is_strictly_inside(&root));
    }

    #[test]
    fn ignore_case_matching_covers_non_ascii() {
        let area = p("C:\\Windows");
        assert!(p("c:\\WINDOWS\\System32").is_at_or_inside_ignore_case(&area));
        assert!(p("C:\\windows").eq_ignore_case(&area));
        assert!(p("C:\\Ünï").eq_ignore_case(&p("C:\\üNÏ")));
        assert!(!p("C:\\Windows.old").is_at_or_inside_ignore_case(&area));
    }

    #[test]
    fn join_refuses_traversal() {
        let root = p("C:\\Temp");
        assert_eq!(root.join(".."), Err(PathError::Relative));
        assert!(root.join("a\\b").is_err());
        assert!(root.join("a:b").is_err());
        assert!(root.join("ok.txt").unwrap().is_strictly_inside(&root));
    }
}
