//! The crash report for a fault during an injected free (decision 3).
//!
//! A fault there ends the run, so the report is the only account of it. Each
//! function is named from the program's own symbol table. A stack word is
//! named only when it falls inside a function, and such a word may be left over
//! from an earlier call, so the stack part is a guess. The faulting address is
//! not shown, because reading it needs `unsafe` code, which this crate forbids.

use std::ops::Range;

use goblin::elf::Elf;
use nix::sys::signal::Signal;

/// The function symbols of a program image, sorted by address.
#[derive(Debug)]
pub struct Symbols {
    /// `(start, size, name)`, sorted, so that equal starts are in a fixed order.
    functions: Vec<(u64, u64, String)>,
}

impl Symbols {
    /// Reads the function symbols of an ELF image. A function with no size
    /// covers no address, so it is left out.
    pub fn parse(image: &[u8]) -> Result<Self, String> {
        let elf = Elf::parse(image).map_err(|error| error.to_string())?;
        let mut functions: Vec<(u64, u64, String)> = elf
            .syms
            .iter()
            .filter(|sym| sym.is_function() && sym.st_size > 0)
            .map(|sym| {
                let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
                (sym.st_value, sym.st_size, name.to_string())
            })
            .collect();
        functions.sort();
        Ok(Symbols { functions })
    }

    /// The function that contains `addr`, and the offset of `addr` in it. When
    /// several functions contain it, the one that starts last is used.
    pub fn locate(&self, addr: u64) -> Option<(&str, u64)> {
        let index = self
            .functions
            .partition_point(|(start, _, _)| *start <= addr);
        self.functions[..index]
            .iter()
            .rev()
            .find(|(start, size, _)| addr < start.saturating_add(*size))
            .map(|(start, _, name)| (name.as_str(), addr - *start))
    }
}

/// The registers and stack of a stopped process.
#[derive(Debug)]
pub struct Snapshot {
    pub regs: libc::user_regs_struct,
    /// The words from the stack pointer upwards, or why they could not be read.
    pub stack: Result<Vec<u64>, String>,
}

/// What a fault left behind. A part that could not be read says why.
#[derive(Debug)]
pub struct Crash {
    pub signal: Signal,
    /// The block whose injected free was running, if any.
    pub freeing: Option<u64>,
    pub state: Result<Snapshot, String>,
    pub symbols: Result<Symbols, String>,
    /// The memory that holds leakgc's own injected code. A fault there is a bug in leakgc.
    pub own_code: Range<u64>,
}

/// The report as lines of text, without the `leakgc:` prefix.
pub fn report(crash: &Crash) -> Vec<String> {
    let mut lines = vec![format!(
        "crash report: {} during an injected free",
        crash.signal
    )];
    if let Some(block) = crash.freeing {
        lines.push(format!("  while freeing the block at 0x{block:x}"));
    }
    match &crash.state {
        Ok(snapshot) => {
            let rip = snapshot.regs.rip;
            lines.push(format!("  crashed at 0x{rip:x}, {}", place(crash, rip)));
            lines.push("  registers:".to_string());
            lines.extend(register_rows(&snapshot.regs));
            lines.extend(stack_lines(&snapshot.stack, &crash.symbols));
        }
        Err(error) => lines.push(format!("  the registers could not be read: {error}")),
    }
    lines.push("  the faulting memory address is not shown".to_string());
    lines.push(
        "  leakgc stops the program here, and its memory report is not trusted from now on"
            .to_string(),
    );
    lines
}

fn place(crash: &Crash, rip: u64) -> String {
    if crash.own_code.contains(&rip) {
        return "in leakgc's own code".to_string();
    }
    match &crash.symbols {
        Ok(symbols) => match symbols.locate(rip) {
            Some((name, offset)) => format!("in {name}+0x{offset:x}"),
            None => "in no known function".to_string(),
        },
        Err(error) => format!("function names are unavailable: {error}"),
    }
}

fn register_rows(regs: &libc::user_regs_struct) -> Vec<String> {
    let values = [
        ("rax", regs.rax),
        ("rbx", regs.rbx),
        ("rcx", regs.rcx),
        ("rdx", regs.rdx),
        ("rsi", regs.rsi),
        ("rdi", regs.rdi),
        ("rbp", regs.rbp),
        ("rsp", regs.rsp),
        ("r8", regs.r8),
        ("r9", regs.r9),
        ("r10", regs.r10),
        ("r11", regs.r11),
        ("r12", regs.r12),
        ("r13", regs.r13),
        ("r14", regs.r14),
        ("r15", regs.r15),
        ("rip", regs.rip),
        ("eflags", regs.eflags),
    ];
    values
        .chunks(4)
        .map(|row| {
            let cells: Vec<String> = row
                .iter()
                .map(|(name, value)| format!("{name:<6} 0x{value:016x}"))
                .collect();
            format!("    {}", cells.join("  "))
        })
        .collect()
}

fn stack_lines(stack: &Result<Vec<u64>, String>, symbols: &Result<Symbols, String>) -> Vec<String> {
    let mut lines = vec![
        "  code addresses on the stack (a guess: some may be left over from earlier calls):"
            .to_string(),
    ];
    match (stack, symbols) {
        (Err(error), _) => lines.push(format!("    the stack could not be read: {error}")),
        (Ok(_), Err(error)) => lines.push(format!("    function names are unavailable: {error}")),
        (Ok(words), Ok(symbols)) => {
            let named: Vec<String> = words
                .iter()
                .filter_map(|&word| {
                    symbols
                        .locate(word)
                        .map(|(name, offset)| format!("    0x{word:x}  {name}+0x{offset:x}"))
                })
                .collect();
            if named.is_empty() {
                lines.push("    none found".to_string());
            } else {
                lines.extend(named);
            }
        }
    }
    lines
}
