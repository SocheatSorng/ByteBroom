//! Grouping duplicates: same size, then the same hash of the first 64 KB, then the same full
//! SHA-256. Pure: the hashing is passed in, so tests can count how often each step runs. Reading
//! files (and refusing cloud placeholders, which a read would download) is the caller's job.

use crate::paths::WinPath;
use std::collections::HashMap;
use std::time::SystemTime;

/// A file that may have copies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The file.
    pub path: WinPath,
    /// Its length.
    pub len: u64,
    /// Its change date.
    pub modified: SystemTime,
}

/// A copy that can go, and the copy that stays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extra {
    /// The copy offered for cleaning.
    pub copy: Candidate,
    /// The copy that is kept: the oldest in its group (ties: the shortest path, then by name).
    pub kept: WinPath,
}

fn split_by<K: std::hash::Hash + Eq>(
    group: Vec<Candidate>,
    mut key: impl FnMut(&Candidate) -> Option<K>,
) -> Vec<Vec<Candidate>> {
    let mut by: HashMap<K, Vec<Candidate>> = HashMap::new();
    for c in group {
        // A file that can't be read (locked, denied, changed) simply leaves the group.
        if let Some(k) = key(&c) {
            by.entry(k).or_default().push(c);
        }
    }
    by.into_values().filter(|g| g.len() > 1).collect()
}

/// The order that decides which copy is kept: oldest first, then shortest path, then by name.
fn keep_order(c: &Candidate) -> (SystemTime, usize, String) {
    let text = c.path.to_string();
    (c.modified, text.len(), text.to_lowercase())
}

/// Every copy that can go, given hashes of the first bytes (`head`) and of the whole file
/// (`full`). `full` runs only for files whose size and head both match another file's.
pub fn find_duplicates(
    candidates: Vec<Candidate>,
    mut head: impl FnMut(&Candidate) -> Option<String>,
    mut full: impl FnMut(&Candidate) -> Option<String>,
) -> Vec<Extra> {
    let mut out = Vec::new();
    for same_size in split_by(candidates, |c| Some(c.len)) {
        for same_head in split_by(same_size, &mut head) {
            for mut group in split_by(same_head, &mut full) {
                group.sort_by_key(keep_order);
                let mut copies = group.into_iter();
                let Some(kept) = copies.next() else {
                    continue;
                };
                out.extend(copies.map(|copy| Extra {
                    copy,
                    kept: kept.path.clone(),
                }));
            }
        }
    }
    out.sort_by_key(|e| e.copy.path.to_string());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn c(path: &str, len: u64, secs: u64) -> Candidate {
        Candidate {
            path: WinPath::parse(path).unwrap_or_else(|e| unreachable!("{e}")),
            len,
            modified: UNIX_EPOCH + Duration::from_secs(secs),
        }
    }

    /// Fake contents: the file name's first letter is its head, the whole name its content.
    fn name(c: &Candidate) -> String {
        c.path.parts().last().cloned().unwrap_or_default()
    }

    #[test]
    fn groups_by_size_then_head_then_content_and_keeps_the_oldest() {
        let files = vec![
            c("C:\\a\\x1", 10, 50),
            c("C:\\b\\x1", 10, 10), // oldest copy of x1: kept
            c("C:\\c\\x1", 10, 90),
            c("C:\\a\\x2", 10, 5), // same size and head as x1, other content
            c("C:\\a\\y1", 10, 1), // same size, other head
            c("C:\\z\\x1", 11, 1), // same name, other size: not a copy
        ];
        let mut heads = 0;
        let mut fulls = Vec::new();
        let got = find_duplicates(
            files,
            |c| {
                heads += 1;
                name(c).get(..1).map(str::to_string)
            },
            |c| {
                fulls.push(c.path.to_string());
                Some(name(c))
            },
        );
        let pairs: Vec<(String, String)> = got
            .iter()
            .map(|e| (e.copy.path.to_string(), e.kept.to_string()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("C:\\a\\x1".to_string(), "C:\\b\\x1".to_string()),
                ("C:\\c\\x1".to_string(), "C:\\b\\x1".to_string()),
            ]
        );
        // Only the five 10-byte files had their heads read; y1's head differs, so it was never
        // fully hashed, and the 11-byte file was never read at all.
        assert_eq!(heads, 5);
        fulls.sort();
        assert_eq!(
            fulls,
            vec!["C:\\a\\x1", "C:\\a\\x2", "C:\\b\\x1", "C:\\c\\x1"]
        );
    }

    #[test]
    fn ties_keep_the_shortest_path() {
        let got = find_duplicates(
            vec![
                c("C:\\long\\er\\f", 1, 7),
                c("C:\\f", 1, 7),
                c("C:\\mid\\f", 1, 7),
            ],
            |_| Some(String::new()),
            |_| Some(String::new()),
        );
        assert!(got.iter().all(|e| e.kept.to_string() == "C:\\f"));
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn unreadable_files_drop_out_and_a_lone_survivor_is_no_duplicate() {
        let got = find_duplicates(
            vec![c("C:\\a", 1, 1), c("C:\\b", 1, 2)],
            |c| (c.path.to_string() != "C:\\b").then(String::new),
            |_| Some(String::new()),
        );
        assert!(got.is_empty());
    }

    #[test]
    fn single_files_are_never_read() {
        let got = find_duplicates(
            vec![c("C:\\a", 1, 1), c("C:\\b", 2, 2)],
            |_| unreachable!("no head needed"),
            |_| unreachable!("no hash needed"),
        );
        assert!(got.is_empty());
    }
}
