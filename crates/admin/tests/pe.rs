//! Review S3: the built helper must tell Windows to load its own imported DLLs from System32
//! only. The flag lives in the PE load-config directory (`DependentLoadFlags`); this reads it
//! straight from the file, independently of the linker.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// The file offset of `rva`, using the section table.
fn offset_of(b: &[u8], pe: usize, rva: u32) -> usize {
    let sections = u16_at(b, pe + 6) as usize;
    let optional = u16_at(b, pe + 20) as usize;
    let table = pe + 24 + optional;
    for i in 0..sections {
        let s = table + i * 40;
        let (size, va, raw) = (u32_at(b, s + 8), u32_at(b, s + 12), u32_at(b, s + 20));
        if rva >= va && rva < va + size.max(u32_at(b, s + 16)) {
            return (rva - va + raw) as usize;
        }
    }
    panic!("rva {rva:#x} in no section");
}

#[test]
fn the_helper_loads_its_own_dlls_from_system32_only() {
    let b = std::fs::read(env!("CARGO_BIN_EXE_bytebroom-admin")).unwrap();
    assert_eq!(&b[..2], b"MZ");
    let pe = u32_at(&b, 0x3C) as usize;
    assert_eq!(&b[pe..pe + 4], b"PE\0\0");
    let opt = pe + 24;
    assert_eq!(u16_at(&b, opt), 0x20B, "a 64-bit program");
    // Data directory 10 is the load configuration (PE32+: directories start at +112).
    let dir = opt + 112 + 10 * 8;
    let (rva, size) = (u32_at(&b, dir), u32_at(&b, dir + 4));
    assert!(rva != 0 && size >= 80, "no load configuration");
    let lc = offset_of(&b, pe, rva);
    // IMAGE_LOAD_CONFIG_DIRECTORY64.DependentLoadFlags is the u16 at offset 0x4E.
    let declared = u32_at(&b, lc) as usize;
    assert!(
        declared >= 0x50,
        "load configuration too old to hold the flag"
    );
    assert_eq!(u16_at(&b, lc + 0x4E), 0x800, "LOAD_LIBRARY_SEARCH_SYSTEM32");
}
