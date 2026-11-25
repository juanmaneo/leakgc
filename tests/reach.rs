//! Reachability of outstanding blocks from registers and writable memory (P4b),
//! with every memory read scripted through the fake tracee. The fake fails on
//! any byte that was not poked, so a read the scan must skip shows up as an error.

mod common;

use std::collections::BTreeSet;
use std::ops::Range;

use common::*;
use leakgc::reach::reachable;

const STACK: (u64, u64) = (0x7fff_e000, 0x7fff_f800);
const RSP: u64 = 0x7fff_f000;
const HEAP: (u64, u64) = (0x6000_0000, 0x6000_4000);
const BLOCKS: (u64, u64) = (0x6100_0000, 0x6100_1000);
/// A hook region far from every mapping, so it excludes nothing by accident.
const FAR_HOOK: Range<u64> = 0x1000_0000..0x1000_1000;

const X: u64 = 0x6100_0000;
const Y: u64 = 0x6100_0100;
const Z: u64 = 0x6100_0200;

fn scene() -> Fake {
    let mut fake = Fake::new(&[], vec![]);
    map_writable(&mut fake, STACK.0, STACK.1);
    map_writable(&mut fake, HEAP.0, HEAP.1);
    map_writable(&mut fake, BLOCKS.0, BLOCKS.1);
    fake
}

fn scan(fake: &mut Fake, blocks: &[(u64, u64)]) -> Result<BTreeSet<u64>, String> {
    reachable(fake, pid(), FAR_HOOK, blocks)
}

fn reached(fake: &mut Fake, blocks: &[(u64, u64)]) -> Vec<u64> {
    scan(fake, blocks)
        .expect("scan completes")
        .into_iter()
        .collect()
}

/// A writable mapping whose first `unreadable` bytes have no contents, so a
/// block at its start cannot be read while the rest of the mapping can.
fn writable_with_unreadable_head(fake: &mut Fake, start: u64, end: u64, unreadable: u64) {
    map_line(fake, start, end, "rw-p");
    for addr in start + unreadable..end {
        fake.mem.entry(addr).or_insert(0);
    }
}

#[test]
fn a_pointer_on_the_stack_above_rsp_keeps_its_block() {
    let mut fake = scene();
    put_word(&mut fake, RSP + 0x100, X);

    assert_eq!(reached(&mut fake, &[(X, 16)]), vec![X]);
}

#[test]
fn an_interior_pointer_keeps_its_block() {
    let mut fake = scene();
    put_word(&mut fake, RSP + 0x100, X + 9);

    assert_eq!(reached(&mut fake, &[(X, 16)]), vec![X]);
}

#[test]
fn every_register_field_is_a_root() {
    let fields: [fn(&mut libc::user_regs_struct) -> &mut u64; 27] = [
        |r| &mut r.r15,
        |r| &mut r.r14,
        |r| &mut r.r13,
        |r| &mut r.r12,
        |r| &mut r.rbp,
        |r| &mut r.rbx,
        |r| &mut r.r11,
        |r| &mut r.r10,
        |r| &mut r.r9,
        |r| &mut r.r8,
        |r| &mut r.rax,
        |r| &mut r.rcx,
        |r| &mut r.rdx,
        |r| &mut r.rsi,
        |r| &mut r.rdi,
        |r| &mut r.orig_rax,
        |r| &mut r.rip,
        |r| &mut r.cs,
        |r| &mut r.eflags,
        |r| &mut r.rsp,
        |r| &mut r.ss,
        |r| &mut r.fs_base,
        |r| &mut r.gs_base,
        |r| &mut r.ds,
        |r| &mut r.es,
        |r| &mut r.fs,
        |r| &mut r.gs,
    ];
    for (index, field) in fields.iter().enumerate() {
        let mut fake = scene();
        *field(&mut fake.regs) = X;

        assert_eq!(reached(&mut fake, &[(X, 16)]), vec![X], "register {index}");
    }
}

#[test]
fn a_block_reached_through_another_block_is_kept() {
    let mut fake = scene();
    put_word(&mut fake, RSP + 0x100, X);
    put_word(&mut fake, X, Y + 4);

    assert_eq!(reached(&mut fake, &[(Y, 16), (X, 16)]), vec![X, Y]);
}

#[test]
fn a_leaked_block_does_not_keep_the_block_it_points_to() {
    let mut fake = scene();
    put_word(&mut fake, X, Y);

    assert!(reached(&mut fake, &[(X, 16), (Y, 16)]).is_empty());
}

#[test]
fn the_red_zone_is_a_root_and_the_stale_stack_below_it_is_not() {
    let mut fake = scene();
    put_word(&mut fake, RSP - 64, X);
    put_word(&mut fake, RSP - 128, Y);
    put_word(&mut fake, RSP - 136, Z);
    put_word(&mut fake, RSP - 256, BLOCKS.0 + 0x300);

    assert_eq!(
        reached(
            &mut fake,
            &[(X, 16), (Y, 16), (Z, 16), (BLOCKS.0 + 0x300, 16)]
        ),
        vec![X, Y]
    );
}

#[test]
fn a_stack_pointer_outside_every_mapping_leaves_the_whole_stack_scanned() {
    let mut fake = scene();
    fake.regs.rsp = 0;
    put_word(&mut fake, STACK.0 + 0x10, X);

    assert_eq!(reached(&mut fake, &[(X, 16)]), vec![X]);
}

#[test]
fn a_hook_region_is_never_read() {
    let mut fake = scene();
    map_line(&mut fake, 0x1000_0000, 0x1000_1000, "rwxp");
    put_word(&mut fake, RSP + 0x100, X);

    assert_eq!(
        reachable(&mut fake, pid(), 0x1000_0000..0x1000_1000, &[(X, 16)]),
        Ok(BTreeSet::from([X]))
    );
}

#[test]
fn the_hook_region_excludes_its_bytes_wherever_it_lies_relative_to_the_heap() {
    // Each case: the hook range, and an address inside the hook where a pointer
    // to X is written. The pointer must not keep X alive. Y is kept by a stack
    // root that lies outside every case.
    let cases: [(Range<u64>, Option<u64>); 6] = [
        (0x5000_0000..0x5000_1000, None),
        (0x7000_0000..0x7000_1000, None),
        (0x5fff_f000..0x6000_1000, Some(0x6000_0100)),
        (0x6000_3000..0x6001_0000, Some(0x6000_3100)),
        (0x5fff_0000..0x6001_0000, Some(0x6000_2000)),
        (0x6000_1000..0x6000_2000, Some(0x6000_1800)),
    ];
    for (hook, inside) in cases {
        let mut fake = scene();
        put_word(&mut fake, RSP + 0x100, Y);
        if let Some(at) = inside {
            put_word(&mut fake, at, X);
        }

        let kept = reachable(&mut fake, pid(), hook.clone(), &[(X, 16), (Y, 16)]);
        let kept = kept.expect("the hook region is not read");
        assert!(kept.contains(&Y), "hook {hook:x?}");
        assert!(!kept.contains(&X), "hook {hook:x?}");
    }
}

#[test]
fn words_on_both_sides_of_a_hole_in_the_heap_are_scanned() {
    let mut fake = scene();
    map_writable(&mut fake, 0x6200_0000, 0x6200_1000);
    put_word(&mut fake, 0x6000_0800, Y);
    put_word(&mut fake, 0x6000_2800, Z);
    put_word(&mut fake, 0x6000_1800, X);
    let hole = 0x6000_1000..0x6000_2000;

    let kept = reachable(&mut fake, pid(), hole, &[(X, 16), (Y, 16), (Z, 16)])
        .expect("the scan completes");

    assert_eq!(kept, BTreeSet::from([Y, Z]));
}

#[test]
fn a_block_touching_the_hook_region_is_excluded_with_it() {
    let mut fake = scene();
    put_word(&mut fake, 0x6000_0800, X);
    put_word(&mut fake, RSP + 0x100, 0x6000_1000 + 4);
    let hook = 0x6000_0000..0x6000_1000;

    let kept = reachable(&mut fake, pid(), hook, &[(0x6000_1000, 16), (X, 16)])
        .expect("the scan completes");

    assert_eq!(kept, BTreeSet::from([0x6000_1000]));
}

#[test]
fn a_root_spanning_several_chunks_is_read_completely() {
    let mut fake = scene();
    map_writable(&mut fake, 0x6500_0000, 0x6502_4000);
    put_word(&mut fake, 0x6500_fff8, X);
    put_word(&mut fake, 0x6502_0000, Y);
    put_word(&mut fake, 0x6502_3ff8, Z);

    assert_eq!(
        reached(&mut fake, &[(X, 16), (Y, 16), (Z, 16)]),
        vec![X, Y, Z]
    );
}

#[test]
fn a_block_size_zero_is_kept_by_its_start_only() {
    let mut fake = scene();
    put_word(&mut fake, RSP + 0x100, X);

    assert_eq!(reached(&mut fake, &[(X, 0), (Y, 0)]), vec![X]);
}

#[test]
fn a_reached_block_outside_every_writable_mapping_is_an_error() {
    let mut fake = scene();
    put_word(&mut fake, RSP + 0x100, 0x6200_0000);

    assert_eq!(
        scan(&mut fake, &[(0x6200_0000, 16)]),
        Err("a reached block could not be read".to_string())
    );
}

#[test]
fn an_unreadable_block_that_nothing_reaches_is_not_an_error() {
    let mut fake = scene();
    writable_with_unreadable_head(&mut fake, 0x6300_0000, 0x6300_1000, 16);

    assert_eq!(
        scan(&mut fake, &[(0x6200_0000, 16), (0x6300_0000, 16)]),
        Ok(BTreeSet::new())
    );
}

#[test]
fn a_reached_block_whose_bytes_cannot_be_read_is_an_error() {
    let mut fake = scene();
    writable_with_unreadable_head(&mut fake, 0x6300_0000, 0x6300_1000, 16);
    put_word(&mut fake, RSP + 0x100, 0x6300_0000);

    assert_eq!(
        scan(&mut fake, &[(0x6300_0000, 16)]),
        Err("a reached block could not be read".to_string())
    );
}

#[test]
fn a_root_range_whose_bytes_cannot_be_read_is_an_error() {
    let mut fake = scene();
    map_line(&mut fake, 0x6400_0000, 0x6400_1000, "rw-p");

    let error = scan(&mut fake, &[]).expect_err("the range cannot be read");

    assert!(
        error.starts_with("a root range could not be read at 0x64000000"),
        "{error}"
    );
}

const READ_ONLY: (u64, u64) = (0x5000_0000, 0x5000_1000);
const CODE: (u64, u64) = (0x5000_2000, 0x5000_3000);
const VVAR: (u64, u64) = (0x5000_4000, 0x5000_5000);

/// A mapping whose bytes are all present, so it can be read.
fn filled_mapping(fake: &mut Fake, start: u64, end: u64, perms: &str) {
    map_line(fake, start, end, perms);
    for addr in start..end {
        fake.mem.entry(addr).or_insert(0);
    }
}

#[test]
fn a_pointer_in_a_read_only_mapping_keeps_its_block() {
    let mut fake = scene();
    filled_mapping(&mut fake, READ_ONLY.0, READ_ONLY.1, "r--p");
    put_word(&mut fake, READ_ONLY.0 + 0x10, X);

    assert_eq!(reached(&mut fake, &[(X, 16)]), vec![X]);
}

#[test]
fn a_pointer_in_an_executable_mapping_is_not_a_root() {
    let mut fake = scene();
    filled_mapping(&mut fake, CODE.0, CODE.1, "r-xp");
    put_word(&mut fake, CODE.0 + 0x10, X);

    assert!(reached(&mut fake, &[(X, 16)]).is_empty());
}

#[test]
fn an_unreadable_read_only_mapping_is_an_error() {
    let mut fake = scene();
    map_line(&mut fake, READ_ONLY.0, READ_ONLY.1, "r--p");

    let error = scan(&mut fake, &[]).expect_err("the range cannot be read");

    assert!(
        error.starts_with("a root range could not be read at 0x50000000"),
        "{error}"
    );
}

#[test]
fn the_kernel_vvar_pages_are_not_scanned() {
    let mut fake = scene();
    fake.maps.push_str(&format!(
        "{:x}-{:x} r--p 00000000 00:00 0 [vvar]\n",
        VVAR.0, VVAR.1
    ));

    assert_eq!(scan(&mut fake, &[]), Ok(BTreeSet::new()));
}

#[test]
fn a_failed_map_read_or_register_read_is_an_error() {
    let mut fake = scene();
    fake.fail_at = Some(0);
    assert_eq!(
        scan(&mut fake, &[]),
        Err("cannot read the memory map: injected maps failure".to_string())
    );

    let mut fake = scene();
    fake.fail_at = Some(1);
    let error = scan(&mut fake, &[]).expect_err("the registers cannot be read");
    assert!(error.starts_with("cannot read the registers:"), "{error}");
}

#[test]
fn a_malformed_or_empty_memory_map_is_an_error() {
    for maps in ["not a mapping\n", "", "00400000-00401000\n"] {
        let mut fake = scene();
        fake.maps = maps.to_string();

        assert_eq!(
            scan(&mut fake, &[]),
            Err("the memory map cannot be parsed".to_string()),
            "maps {maps:?}"
        );
    }
}

#[test]
fn overlapping_or_duplicate_blocks_are_an_error() {
    let overlapping = [(X, 32), (X + 16, 16)];
    let duplicate = [(X, 0), (X, 0)];

    for blocks in [&overlapping[..], &duplicate[..]] {
        let mut fake = scene();
        assert_eq!(
            scan(&mut fake, blocks),
            Err("outstanding blocks overlap".to_string()),
            "{blocks:?}"
        );
    }
}
