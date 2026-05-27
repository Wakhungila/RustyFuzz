use crate::satori::error::SatoriResult;
use crate::satori::fsutil::write_json;
use crate::satori::types::SatoriReport;
use std::path::Path;

pub fn write_report_json(run_dir: &Path, report: &SatoriReport) -> SatoriResult<()> {
    write_json(run_dir.join("report.json"), report)
}
