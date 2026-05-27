use crate::satori::error::SatoriResult;
use crate::satori::fsutil::write_text;
use crate::satori::report::json::write_report_json;
use crate::satori::report::markdown::render_markdown;
use crate::satori::types::SatoriReport;
use std::path::Path;

pub fn write_reports(run_dir: &Path, report: &SatoriReport) -> SatoriResult<()> {
    write_report_json(run_dir, report)?;
    let md = render_markdown(report);
    write_text(run_dir.join("report.md"), &md)?;
    write_text("satori/reports/latest.md", &md)?;
    Ok(())
}
