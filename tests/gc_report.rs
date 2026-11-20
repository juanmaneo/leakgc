//! Report text and the optional report output of `collect`.

use std::io::{self, Write};

use leakgc::gc::{Heap, LeakReport, SiteLoss, render_report};

/// A writer whose every write fails, to exercise the error path of `collect`.
struct BrokenWriter;

impl Write for BrokenWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("disk full"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn clean_report_uses_the_oracle_wording() {
    let report = LeakReport {
        retained_bytes: 4608,
        ..LeakReport::default()
    };
    assert_eq!(
        render_report(&report),
        "\n== LEAKCHECK SUMMARY ==\n\
         \x20  no leaks are possible: all blocks reachable from roots\n\
         \x20  retained (live) heap: 4608 bytes\n\
         == END SUMMARY ==\n"
    );
}

#[test]
fn leaky_report_lists_each_site_in_order() {
    let report = LeakReport {
        total_lost_blocks: 4,
        total_lost_bytes: 262144,
        by_site: vec![
            SiteLoss {
                site: "load_level_textures:210".to_owned(),
                blocks: 4,
                bytes: 262144,
            },
            SiteLoss {
                site: "build_node:41".to_owned(),
                blocks: 3,
                bytes: 192,
            },
        ],
        retained_bytes: 4608,
    };
    assert_eq!(
        render_report(&report),
        "\n== LEAKCHECK SUMMARY ==\n\
         \x20  definitely lost: 4 blocks in 262144 bytes\n\
         \x20    at load_level_textures:210: 4 block(s), 262144 bytes\n\
         \x20    at build_node:41: 3 block(s), 192 bytes\n\
         \x20  retained (live) heap: 4608 bytes\n\
         == END SUMMARY ==\n"
    );
}

#[test]
fn collect_writes_the_summary_when_given_a_writer() {
    let mut heap = Heap::new();
    heap.alloc(&[], "build_node:41", 64);
    let mut out: Vec<u8> = Vec::new();

    let report = heap
        .collect(true, Some(&mut out))
        .expect("writing to a Vec cannot fail");

    assert_eq!(
        String::from_utf8(out).expect("report is UTF-8"),
        render_report(&report)
    );
}

#[test]
fn collect_without_a_writer_returns_the_report_silently() {
    let mut heap = Heap::new();
    heap.alloc(&[], "leak", 8);

    let report = heap.collect(true, None).expect("no writer, no io error");

    assert_eq!(report.total_lost_blocks, 1);
    assert_eq!(heap.collections(), 1);
}

#[test]
fn collect_sweeps_before_reporting_a_write_error() {
    let mut heap = Heap::new();
    heap.alloc(&[], "leak", 8);

    let error = heap
        .collect(true, Some(&mut BrokenWriter))
        .expect_err("the writer always fails");

    assert_eq!(error.to_string(), "disk full");
    assert_eq!(heap.blocks().count(), 0);
}
