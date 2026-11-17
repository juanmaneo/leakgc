//! Golden transcript: the demo must reproduce the output of
//! `ocaml ocaml/leakcheck.ml` byte for byte.

use win_games_leak_garbage_collector::gc::demo_transcript;

const ORACLE_OUTPUT: &str = r#"--- scenario 1: well-behaved code ---

== LEAKCHECK SUMMARY ==
   no leaks are possible: all blocks reachable from roots
   retained (live) heap: 4608 bytes
== END SUMMARY ==

--- scenario 2: cyclic garbage (unreachable ring) ---

== LEAKCHECK SUMMARY ==
   definitely lost: 3 blocks in 192 bytes
     at build_node:41: 3 block(s), 192 bytes
   retained (live) heap: 4608 bytes
== END SUMMARY ==

--- scenario 3: the old Windows game pattern ---

== LEAKCHECK SUMMARY ==
   definitely lost: 4 blocks in 262144 bytes
     at load_level_textures:210: 4 block(s), 262144 bytes
   retained (live) heap: 4608 bytes
== END SUMMARY ==

done: 3 collections, 266944 bytes total allocated
"#;

#[test]
fn demo_transcript_matches_the_oracle_output() {
    assert_eq!(demo_transcript(), ORACLE_OUTPUT);
}
