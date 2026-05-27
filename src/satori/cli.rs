use crate::satori::error::SatoriResult;
use crate::satori::fsutil::read_json;
use crate::satori::pipeline::{
    build_report_for_existing_run, ingest_graph_packets, run_model_audit,
};
use crate::satori::types::SatoriConfig;
use clap::{ArgAction, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum SatoriCommand {
    Ingest {
        path: PathBuf,
    },
    Graph {
        path: PathBuf,
    },
    Packets {
        path: PathBuf,
        #[arg(long, default_value_t = 8)]
        max_critical_functions: usize,
    },
    Model {
        path: PathBuf,
        #[arg(long, default_value = "o3")]
        model: String,
    },
    Hunt {
        path: PathBuf,
        #[arg(long, default_value = "o3")]
        model: String,
        #[arg(long, default_value_t = 8)]
        max_critical_functions: usize,
        #[arg(long, default_value_t = 2)]
        max_hypotheses_per_function: usize,
        #[arg(long, default_value_t = 0.40)]
        min_confidence: f64,
    },
    Validate {
        run_id: String,
    },
    Audit {
        path: PathBuf,
        #[arg(long, default_value = "o3")]
        model: String,
        #[arg(long, default_value_t = 8)]
        max_critical_functions: usize,
        #[arg(long, default_value_t = 2)]
        max_hypotheses_per_function: usize,
        #[arg(long, default_value_t = 0.40)]
        min_confidence: f64,
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        validate: bool,
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        generate_jobs: bool,
    },
    Report {
        run_id: String,
    },
}

pub async fn run(command: SatoriCommand) -> SatoriResult<()> {
    match command {
        SatoriCommand::Ingest { path } => {
            let config = SatoriConfig::default();
            let artifacts = ingest_graph_packets(&path, config, 0)?;
            println!(
                "Satori ingest complete: run_id={}, project={}",
                artifacts.run.run_id,
                artifacts.project.root.display()
            );
        }
        SatoriCommand::Graph { path } => {
            let config = SatoriConfig::default();
            let artifacts = ingest_graph_packets(&path, config, 8)?;
            println!(
                "Satori graph complete: run_id={}, functions={}",
                artifacts.run.run_id,
                artifacts.analysis.functions.len()
            );
        }
        SatoriCommand::Packets {
            path,
            max_critical_functions,
        } => {
            let config = SatoriConfig::default();
            let artifacts = ingest_graph_packets(&path, config, max_critical_functions)?;
            println!(
                "Satori packets complete: run_id={}, max_critical_functions={}",
                artifacts.run.run_id, max_critical_functions
            );
        }
        SatoriCommand::Model { path, model } => {
            require_llm_feature()?;
            let config = SatoriConfig {
                model,
                validate: false,
                generate_jobs: false,
                ..SatoriConfig::default()
            };
            let report = run_model_audit(&path, config).await?;
            println!(
                "Satori model run complete: run_id={}, hypotheses={}",
                report.run_id,
                report.hypotheses.len()
            );
        }
        SatoriCommand::Hunt {
            path,
            model,
            max_critical_functions,
            max_hypotheses_per_function,
            min_confidence,
        } => {
            require_llm_feature()?;
            let config = SatoriConfig {
                model,
                max_critical_functions,
                max_hypotheses_per_function,
                min_confidence,
                validate: true,
                generate_jobs: true,
                ..SatoriConfig::default()
            };
            let report = run_model_audit(&path, config).await?;
            println!(
                "Satori hunt complete: run_id={}, hypotheses={}, jobs={}, verdicts={}",
                report.run_id,
                report.hypotheses.len(),
                report.jobs.len(),
                report.validation_verdicts.len()
            );
        }
        SatoriCommand::Audit {
            path,
            model,
            max_critical_functions,
            max_hypotheses_per_function,
            min_confidence,
            validate,
            generate_jobs,
        } => {
            require_llm_feature()?;
            let config = SatoriConfig {
                model,
                max_critical_functions,
                max_hypotheses_per_function,
                min_confidence,
                validate,
                generate_jobs,
                ..SatoriConfig::default()
            };
            let report = run_model_audit(&path, config).await?;
            println!(
                "Satori audit complete: run_id={}, report=satori/runs/{}/report.md",
                report.run_id, report.run_id
            );
        }
        SatoriCommand::Validate { run_id } => {
            let _run: crate::satori::types::SatoriRun =
                read_json(PathBuf::from("satori/runs").join(&run_id).join("run.json"))?;
            let report = build_report_for_existing_run(&run_id)?;
            println!(
                "Satori validation/report refresh complete: run_id={}, verdicts={}",
                report.run_id,
                report.validation_verdicts.len()
            );
        }
        SatoriCommand::Report { run_id } => {
            let report = build_report_for_existing_run(&run_id)?;
            println!(
                "Satori report written: satori/runs/{}/report.md (hypotheses={}, verdicts={})",
                report.run_id,
                report.hypotheses.len(),
                report.validation_verdicts.len()
            );
        }
    }
    Ok(())
}

fn require_llm_feature() -> SatoriResult<()> {
    #[cfg(feature = "llm")]
    {
        Ok(())
    }
    #[cfg(not(feature = "llm"))]
    {
        Err(crate::satori::error::llm_feature_required())
    }
}
