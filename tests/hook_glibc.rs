//! The planner accepts the glibc entry points that the hooks patch, read from a
//! real static binary. The images are built from `malloc_static.c` with `cc`.

use std::path::Path;
use std::process::Command;

use goblin::elf::Elf;
use goblin::elf::section_header::SHT_NOBITS;
use leakgc::hook::{Plan, Refusal, plan};

const ENTRY: u64 = 0x1000_0000;
const DISPLACED: u64 = ENTRY + 0x180;

fn static_image() -> Vec<u8> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/malloc_static.c");
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("hook_glibc_static");
    let status = Command::new("cc")
        .arg(&src)
        .args(["-static", "-no-pie", "-o"])
        .arg(&out)
        .status()
        .expect("run cc");
    assert!(status.success(), "cc failed for the malloc fixture");
    std::fs::read(&out).expect("read the built image")
}

fn plan_symbol(image: &[u8], name: &str) -> Result<Plan, Refusal> {
    let elf = Elf::parse(image).expect("fixture parses");
    let sym = elf
        .syms
        .iter()
        .find(|sym| sym.is_function() && elf.strtab.get_at(sym.st_name) == Some(name))
        .expect("symbol present");
    let text: Vec<(u64, &[u8])> = elf
        .section_headers
        .iter()
        .filter(|sh| sh.is_executable() && sh.sh_type != SHT_NOBITS && sh.sh_size > 0)
        .map(|sh| {
            let start = sh.sh_offset as usize;
            let end = start + sh.sh_size as usize;
            (sh.sh_addr, &image[start..end])
        })
        .collect();
    let function = text
        .iter()
        .find(|(start, code)| (*start..*start + code.len() as u64).contains(&sym.st_value))
        .map(|(start, code)| {
            let from = (sym.st_value - start) as usize;
            &code[from..from + sym.st_size as usize]
        })
        .expect("symbol lies in an executable section");
    plan(sym.st_value, function, &text, ENTRY, DISPLACED)
}

#[test]
fn the_planner_accepts_every_hooked_entry() {
    let image = static_image();
    let mut names = vec![
        "malloc",
        "free",
        "realloc",
        "calloc",
        "memalign",
        "aligned_alloc",
        "valloc",
        "posix_memalign",
    ];
    // musl has neither `pvalloc` nor `malloc_trim`.
    if cfg!(target_env = "gnu") {
        names.extend(["pvalloc", "malloc_trim"]);
    }
    for name in names {
        let planned = plan_symbol(&image, name);
        assert!(planned.is_ok(), "{name} refused: {planned:?}");
    }
}
