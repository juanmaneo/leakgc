use super::LeakReport;

/// Renders the summary that `print_report` writes in the oracle, byte for byte.
pub fn render_report(report: &LeakReport) -> String {
    let mut text = String::from("\n== LEAKCHECK SUMMARY ==\n");
    if report.total_lost_blocks == 0 {
        text.push_str("   no leaks are possible: all blocks reachable from roots\n");
    } else {
        text.push_str(&format!(
            "   definitely lost: {} blocks in {} bytes\n",
            report.total_lost_blocks, report.total_lost_bytes
        ));
        for loss in &report.by_site {
            text.push_str(&format!(
                "     at {}: {} block(s), {} bytes\n",
                loss.site, loss.blocks, loss.bytes
            ));
        }
    }
    text.push_str(&format!(
        "   retained (live) heap: {} bytes\n",
        report.retained_bytes
    ));
    text.push_str("== END SUMMARY ==\n");
    text
}
