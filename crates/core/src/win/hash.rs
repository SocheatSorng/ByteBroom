//! SHA-256 through Windows' own CNG (bcrypt.dll): no extra crate, and a vetted implementation.

use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_HASH_HANDLE, BCRYPT_SHA256_ALG_HANDLE, BCryptCreateHash, BCryptDestroyHash,
    BCryptFinishHash, BCryptHashData,
};

/// A running SHA-256 hash.
pub struct Sha256 {
    handle: BCRYPT_HASH_HANDLE,
}

impl Sha256 {
    /// Start a new hash. `None` if Windows refused (never expected on Windows 10+).
    pub fn new() -> Option<Self> {
        let mut handle: BCRYPT_HASH_HANDLE = std::ptr::null_mut();
        // SAFETY: the pseudo-handle for SHA-256 is valid on Windows 10+; a null hash object
        // buffer lets CNG allocate it; no secret (not an HMAC).
        let status = unsafe {
            BCryptCreateHash(
                BCRYPT_SHA256_ALG_HANDLE,
                &mut handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                0,
                0,
            )
        };
        (status == 0 && !handle.is_null()).then_some(Self { handle })
    }

    /// Add bytes. Returns false if Windows reported an error.
    pub fn update(&mut self, mut data: &[u8]) -> bool {
        while !data.is_empty() {
            let take = data.len().min(u32::MAX as usize);
            // SAFETY: `data[..take]` is readable; the hash handle is live.
            let status = unsafe { BCryptHashData(self.handle, data.as_ptr(), take as u32, 0) };
            if status != 0 {
                return false;
            }
            data = &data[take..];
        }
        true
    }

    /// The digest as 64 upper-case hex characters (the same form as `Get-FileHash`).
    pub fn finish_hex(self) -> Option<String> {
        let mut digest = [0u8; 32];
        // SAFETY: `digest` is writable for 32 bytes, the SHA-256 output size.
        let status = unsafe { BCryptFinishHash(self.handle, digest.as_mut_ptr(), 32, 0) };
        (status == 0).then(|| digest.iter().map(|b| format!("{b:02X}")).collect())
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        // SAFETY: the handle came from BCryptCreateHash and is destroyed exactly once.
        unsafe {
            BCryptDestroyHash(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_published_test_vectors() {
        let mut h = Sha256::new().unwrap();
        assert!(h.update(b"abc"));
        assert_eq!(
            h.finish_hex().unwrap(),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
        let empty = Sha256::new().unwrap().finish_hex().unwrap();
        assert_eq!(
            empty,
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
    }

    #[test]
    fn hashing_in_pieces_equals_hashing_at_once() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let mut whole = Sha256::new().unwrap();
        whole.update(&data);
        let mut parts = Sha256::new().unwrap();
        for chunk in data.chunks(777) {
            parts.update(chunk);
        }
        assert_eq!(whole.finish_hex(), parts.finish_hex());
    }
}
