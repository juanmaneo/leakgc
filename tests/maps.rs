use leakgc::maps::{ScanRanges, scan_ranges, writable_count};

#[test]
fn counts_only_mappings_with_write_permission() {
    let sample = "\
00400000-00401000 r-xp 00000000 08:01 1 /bin/game
00601000-00602000 rw-p 00001000 08:01 1 /bin/game
7f000000-7f001000 rwxp 00000000 00:00 0
7fff0000-7fff1000 ---p 00000000 00:00 0
";
    assert_eq!(writable_count(sample), 2);
}

#[test]
fn ignores_empty_and_malformed_lines() {
    assert_eq!(writable_count(""), 0);
    assert_eq!(writable_count("\n\n"), 0);
    assert_eq!(writable_count("00400000-00401000"), 0);
    assert_eq!(writable_count("00400000-00401000 r"), 0);
}

#[test]
fn roots_are_writable_and_readable_non_executable_mappings() {
    let sample = "\
00400000-00401000 r-xp 00000000 08:01 1 /bin/game
00401000-00402000 r--p 00001000 08:01 1 /bin/game
00601000-00602000 rw-p 00001000 08:01 1 /bin/game
7f000000-7f001000 rwxp 00000000 00:00 0
7f001000-7f002000 r--s 00000000 00:05 9 /dev/zero
7f002000-7f003000 -w-p 00000000 00:00 0
7fff0000-7fff1000 ---p 00000000 00:00 0
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]
";
    assert_eq!(
        scan_ranges(sample),
        Some(ScanRanges {
            writable: vec![
                (0x601000, 0x602000),
                (0x7f00_0000, 0x7f00_1000),
                (0x7f00_2000, 0x7f00_3000),
            ],
            roots: vec![
                (0x401000, 0x402000),
                (0x601000, 0x602000),
                (0x7f00_0000, 0x7f00_1000),
                (0x7f00_1000, 0x7f00_2000),
                (0x7f00_2000, 0x7f00_3000),
            ],
        })
    );
}

#[test]
fn the_kernel_vvar_pages_are_not_roots() {
    let sample = "\
7f000000-7f004000 r--p 00000000 00:00 0 [vvar]
7f004000-7f006000 r--p 00000000 00:00 0 [vvar_vclock]
";
    assert_eq!(scan_ranges(sample), Some(ScanRanges::default()));
}

#[test]
fn an_empty_map_has_no_ranges() {
    assert_eq!(scan_ranges(""), Some(ScanRanges::default()));
}

#[test]
fn scan_ranges_is_none_when_any_line_does_not_parse() {
    let malformed = [
        "not a mapping\n",
        "00400000-00401000\n",
        "00400000 rw-p\n",
        "zz-00401000 rw-p\n",
        "00400000-zz rw-p\n",
        "00401000-00400000 rw-p\n",
        "00600000-00601000 rw-p 00000000 00:00 0\nnot a mapping\n",
        "00600000-00601000 rw-p 00000000 00:00 0\n\n",
    ];
    for maps in malformed {
        assert_eq!(scan_ranges(maps), None, "maps {maps:?}");
    }
}
