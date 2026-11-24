use leakgc::maps::{writable_count, writable_ranges};

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
fn writable_ranges_lists_the_writable_mappings_in_order() {
    let sample = "\
00400000-00401000 r-xp 00000000 08:01 1 /bin/game
00601000-00602000 rw-p 00001000 08:01 1 /bin/game
7f000000-7f001000 rwxp 00000000 00:00 0
7fff0000-7fff1000 ---p 00000000 00:00 0
";
    assert_eq!(
        writable_ranges(sample),
        Some(vec![(0x601000, 0x602000), (0x7f00_0000, 0x7f00_1000)])
    );
}

#[test]
fn writable_ranges_of_an_empty_map_is_empty() {
    assert_eq!(writable_ranges(""), Some(vec![]));
}

#[test]
fn writable_ranges_is_none_when_any_line_does_not_parse() {
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
        assert_eq!(writable_ranges(maps), None, "maps {maps:?}");
    }
}
