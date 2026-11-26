use leakgc::maps::{ScanRanges, find_gap, scan_ranges, writable_count};

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
7f003000-7f004000 rw-s 00000000 00:05 9 /dev/shm/game
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
                (0x7f00_3000, 0x7f00_4000),
            ],
            private: vec![
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
                (0x7f00_3000, 0x7f00_4000),
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

#[test]
fn find_gap_is_none_when_any_line_does_not_parse() {
    let malformed = [
        "\n",
        "not a mapping\n",
        "00400000 rw-p\n",
        "zz-00401000 rw-p\n",
        "00400000-zz rw-p\n",
        "00401000-00400000 rw-p\n",
        "00600000-00601000 rw-p\nnot a mapping\n",
    ];
    for maps in malformed {
        assert_eq!(find_gap(maps, 0..0x10000, 1, 1), None, "maps {maps:?}");
    }
}

#[test]
fn find_gap_returns_the_window_start_when_nothing_is_mapped() {
    assert_eq!(find_gap("", 0x1001..0x9000, 0x100, 0x1000), Some(0x2000));
}

#[test]
fn find_gap_ignores_a_mapping_that_ends_before_the_window() {
    assert_eq!(
        find_gap("00000100-00000800 rw-p\n", 0x1000..0x2000, 0x1000, 1),
        Some(0x1000)
    );
}

#[test]
fn find_gap_uses_a_gap_before_the_first_mapping() {
    assert_eq!(
        find_gap("00004000-00005000 rw-p\n", 0x1000..0x9000, 0x2000, 1),
        Some(0x1000)
    );
}

#[test]
fn find_gap_moves_past_a_mapping_that_overlaps_the_window_start() {
    let maps = "00000f00-00002100 rw-p\n";
    assert_eq!(find_gap(maps, 0x1000..0x9000, 0x100, 1), Some(0x2100));
    assert_eq!(find_gap(maps, 0x1000..0x9000, 0x100, 0x1000), Some(0x3000));
}

#[test]
fn find_gap_skips_a_gap_that_is_too_small() {
    let maps = "00002000-00003000 rw-p\n00003800-00004000 rw-p\n";
    assert_eq!(find_gap(maps, 0x1000..0x8000, 0x1000, 1), Some(0x1000));
    assert_eq!(find_gap(maps, 0x1000..0x8000, 0x1800, 1), Some(0x4000));
}

#[test]
fn find_gap_sorts_the_mappings_before_it_scans_them() {
    let maps = "00004000-00005000 rw-p\n00002000-00003000 rw-p\n";
    assert_eq!(find_gap(maps, 0x2000..0x6000, 0x1000, 1), Some(0x3000));
}

#[test]
fn find_gap_is_none_when_the_window_is_too_small() {
    let maps = "00002000-00003000 rw-p\n";
    assert_eq!(find_gap(maps, 0x1000..0x2800, 0x1800, 1), None);
    assert_eq!(find_gap(maps, 0x1000..0x2800, 0x1000, 1), Some(0x1000));
    assert_eq!(find_gap("", 0x1000..0x2000, 0x1000, 1), Some(0x1000));
}

#[test]
fn find_gap_treats_align_zero_as_one() {
    assert_eq!(find_gap("", 0x1001..0x2000, 1, 0), Some(0x1001));
}

#[test]
fn find_gap_is_none_on_address_overflow() {
    assert_eq!(find_gap("", u64::MAX..u64::MAX, 1, 0x1000), None);
    assert_eq!(find_gap("", (u64::MAX - 0x10)..u64::MAX, 0x100, 1), None);
    assert_eq!(
        find_gap(
            "00001000-ffffffffffffffff rw-p\n",
            0x1000..u64::MAX,
            0x100,
            0x1000
        ),
        None
    );
}

#[test]
fn find_gap_places_the_hook_region_in_the_wine_ntdll_gap() {
    let maps = include_str!("fixtures/wine_ntdll.maps");
    let window = 0x6fff_83ba_1000..0x7000_7bc2_3000;
    let len = 64 << 20;
    assert_eq!(
        find_gap(maps, window, len, 0x1_0000),
        Some(0x6fff_83bb_0000)
    );
}
