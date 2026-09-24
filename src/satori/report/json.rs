use crate::satori::error::SatoriResult;
use crate::satori::fsutil::write_json_in_run;
use crate::satori::types::SatoriReport;
use std::path::Path;

pub fn write_report_json(run_dir: &Path, report: &SatoriReport) -> SatoriResult<()> {
    write_json_in_run(run_dir, Path::new("report.json"), report)
}
