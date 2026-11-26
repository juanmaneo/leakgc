//! The crash report for a fault during an injected free: symbol lookup and the
//! text of the report (decision 3).

mod common;

use std::ops::Range;

use goblin::elf::Elf;
use leakgc::crash::{Crash, Snapshot, Symbols, report};
use nix::sys::signal::Signal;

const OWN_CODE: Range<u64> = 0x6000_0000..0x6001_0000;
const FAULT_LINE: &str = "  the faulting memory address is not shown";
const STOP_LINE: &str =
    "  leakgc stops the program here, and its memory report is not trusted from now on";
const STACK_HEADING: &str =
    "  code addresses on the stack (a guess: some may be left over from earlier calls):";

fn symbol(name: &str) -> (u64, u64) {
    let image = common::static_image();
    let elf = Elf::parse(image).expect("the fixture parses");
    elf.syms
        .iter()
        .find(|sym| {
            sym.is_function() && sym.st_size > 0 && elf.strtab.get_at(sym.st_name) == Some(name)
        })
        .map(|sym| (sym.st_value, sym.st_size))
        .expect("the fixture has the function")
}

fn fixture_symbols() -> Symbols {
    Symbols::parse(common::static_image()).expect("the fixture parses")
}

/// A fault at `rip`, with `rax` set so that one register row is recognisable.
fn fault_at(rip: u64, stack: Vec<u64>) -> Crash {
    let mut regs = common::initial_regs(rip);
    regs.rax = 1;
    Crash {
        signal: Signal::SIGSEGV,
        freeing: Some(0x8000),
        state: Ok(Snapshot {
            regs,
            stack: Ok(stack),
        }),
        symbols: Ok(fixture_symbols()),
        own_code: OWN_CODE,
    }
}

#[test]
fn an_image_that_is_not_an_elf_has_no_symbols() {
    assert!(Symbols::parse(b"not an elf").is_err());
}

#[test]
fn an_address_inside_a_function_is_named_with_its_offset() {
    let symbols = fixture_symbols();
    let (start, size) = symbol("_int_malloc");

    assert_eq!(symbols.locate(start), Some(("_int_malloc", 0)));
    assert_eq!(
        symbols.locate(start + size - 1),
        Some(("_int_malloc", size - 1))
    );
}

#[test]
fn an_address_outside_every_function_is_named_by_nothing() {
    let symbols = fixture_symbols();

    assert_eq!(symbols.locate(0), None);
    assert_eq!(symbols.locate(u64::MAX), None);
}

#[test]
fn a_fault_names_the_block_the_function_the_registers_and_the_stack() {
    let (start, _) = symbol("_int_malloc");
    let crash = fault_at(start + 0x10, vec![start + 0x20, 42]);

    let lines = report(&crash);

    assert_eq!(lines[0], "crash report: SIGSEGV during an injected free");
    assert_eq!(lines[1], "  while freeing the block at 0x8000");
    assert_eq!(
        lines[2],
        format!("  crashed at 0x{:x}, in _int_malloc+0x10", start + 0x10)
    );
    assert_eq!(lines[3], "  registers:");
    assert!(
        lines[4].starts_with("    rax    0x0000000000000001  rbx    0x"),
        "{}",
        lines[4]
    );
    assert!(lines[7].contains("  r15    0x"), "{}", lines[7]);
    assert!(
        lines[8].starts_with("    rip    0x") && lines[8].contains("  eflags 0x"),
        "{}",
        lines[8]
    );
    let tail = [
        STACK_HEADING.to_string(),
        format!("    0x{:x}  _int_malloc+0x20", start + 0x20),
        FAULT_LINE.to_string(),
        STOP_LINE.to_string(),
    ];
    assert!(lines.ends_with(&tail), "{lines:?}");
}

#[test]
fn a_fault_outside_every_function_says_so_and_names_no_stack_word() {
    let lines = report(&fault_at(1, vec![42]));

    assert_eq!(lines[2], "  crashed at 0x1, in no known function");
    assert!(lines.ends_with(&[
        STACK_HEADING.to_string(),
        "    none found".to_string(),
        FAULT_LINE.to_string(),
        STOP_LINE.to_string(),
    ]));
}

#[test]
fn a_fault_in_leakgc_own_code_is_named_as_such() {
    let lines = report(&fault_at(OWN_CODE.start + 0x40, vec![]));

    assert_eq!(
        lines[2],
        format!(
            "  crashed at 0x{:x}, in leakgc's own code",
            OWN_CODE.start + 0x40
        )
    );
}

#[test]
fn a_crash_without_a_block_leaves_out_the_block_line() {
    let mut crash = fault_at(1, vec![]);
    crash.freeing = None;

    let lines = report(&crash);

    assert_eq!(lines[0], "crash report: SIGSEGV during an injected free");
    assert_eq!(lines[1], "  crashed at 0x1, in no known function");
}

#[test]
fn unreadable_registers_are_reported_and_the_dump_is_left_out() {
    let crash = Crash {
        state: Err("EIO: Input/output error".to_string()),
        ..fault_at(1, vec![])
    };

    let lines = report(&crash);

    assert_eq!(
        lines,
        [
            "crash report: SIGSEGV during an injected free".to_string(),
            "  while freeing the block at 0x8000".to_string(),
            "  the registers could not be read: EIO: Input/output error".to_string(),
            FAULT_LINE.to_string(),
            STOP_LINE.to_string(),
        ]
    );
}

#[test]
fn an_unreadable_stack_is_reported_under_the_stack_heading() {
    let crash = Crash {
        state: Ok(Snapshot {
            regs: common::initial_regs(1),
            stack: Err("injected read failure".to_string()),
        }),
        ..fault_at(1, vec![])
    };

    let lines = report(&crash);

    assert!(lines.ends_with(&[
        STACK_HEADING.to_string(),
        "    the stack could not be read: injected read failure".to_string(),
        FAULT_LINE.to_string(),
        STOP_LINE.to_string(),
    ]));
}

#[test]
fn unreadable_symbols_leave_the_names_out() {
    let (start, _) = symbol("_int_malloc");
    let crash = Crash {
        symbols: Err("bad image".to_string()),
        ..fault_at(start + 0x10, vec![start + 0x20])
    };

    let lines = report(&crash);

    assert_eq!(
        lines[2],
        format!(
            "  crashed at 0x{:x}, function names are unavailable: bad image",
            start + 0x10
        )
    );
    assert!(lines.ends_with(&[
        STACK_HEADING.to_string(),
        "    function names are unavailable: bad image".to_string(),
        FAULT_LINE.to_string(),
        STOP_LINE.to_string(),
    ]));
}

#[test]
fn leakgc_own_code_is_named_even_when_symbols_are_unavailable() {
    let crash = Crash {
        symbols: Err("bad image".to_string()),
        ..fault_at(OWN_CODE.start, vec![])
    };

    let lines = report(&crash);

    assert_eq!(
        lines[2],
        format!("  crashed at 0x{:x}, in leakgc's own code", OWN_CODE.start)
    );
}
