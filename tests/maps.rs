use leakgc::maps::writable_count;

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
