//! Memory-related system calls that the stub's seccomp filter reports to the
//! supervisor. Every other system call runs natively, without a stop.

/// Trapped system calls, with the names used in logs (D18).
pub const TRAPPED: &[(i64, &str)] = &[
    (libc::SYS_mmap, "mmap"),
    (libc::SYS_munmap, "munmap"),
    (libc::SYS_mremap, "mremap"),
    (libc::SYS_brk, "brk"),
    (libc::SYS_clone, "clone"),
    (libc::SYS_clone3, "clone3"),
    (libc::SYS_execve, "execve"),
];

pub fn name_of(nr: i64) -> &'static str {
    TRAPPED
        .iter()
        .find(|(trapped, _)| *trapped == nr)
        .map_or("unknown", |(_, name)| name)
}
