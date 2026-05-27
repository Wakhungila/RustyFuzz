use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{collect_files, read_lossy_limited, sha256_hex, write_json};
use crate::satori::ingest::foundry::is_foundry_project;
use crate::satori::ingest::hardhat::is_hardhat_project;
use crate::satori::types::{ProjectModel, ProjectType, ProtocolType, SourceFile};
use std::path::{Path, PathBuf};

pub fn ingest_project(root: &Path, run_dir: &Path) -> SatoriResult<ProjectModel> {
    let root = root.canonicalize()?;
    let files = collect_files(&root)?;
    let mut source_files = Vec::new();
    let mut test_files = Vec::new();
    let mut docs = Vec::new();

    for file in files {
        let rel = file.strip_prefix(&root).unwrap_or(&file).to_path_buf();
        let rel_s = rel.to_string_lossy();
        let extension = file.extension().and_then(|ext| ext.to_str()).unwrap_or("");
        if extension == "sol" || extension == "vy" {
            let source = source_file(&root, &file, extension)?;
            if rel_s.starts_with("test/")
                || rel_s.starts_with("tests/")
                || rel_s.contains("/test/")
                || rel_s.contains("/tests/")
            {
                test_files.push(rel);
            } else {
                source_files.push(source);
            }
        } else if is_doc_file(&file) {
            docs.push(source_file(&root, &file, "markdown")?);
        }
    }

    let foundry_toml = root
        .join("foundry.toml")
        .exists()
        .then(|| root.join("foundry.toml"));
    let hardhat_config = ["hardhat.config.js", "hardhat.config.ts"]
        .iter()
        .map(|name| root.join(name))
        .find(|path| path.exists());
    let package_json = root
        .join("package.json")
        .exists()
        .then(|| root.join("package.json"));
    let remappings = root
        .join("remappings.txt")
        .exists()
        .then(|| root.join("remappings.txt"));
    let project_type = classify_project(&root, &source_files);

    let model = ProjectModel {
        root,
        project_type,
        source_files,
        test_files,
        docs,
        foundry_toml,
        hardhat_config,
        package_json,
        remappings,
        detected_protocols: Vec::from([ProtocolType::Unknown]),
    };
    write_json(run_dir.join("project.json"), &model)?;
    Ok(model)
}

fn classify_project(root: &Path, source_files: &[SourceFile]) -> ProjectType {
    let foundry = is_foundry_project(root);
    let hardhat = is_hardhat_project(root);
    if foundry && hardhat {
        ProjectType::Mixed
    } else if foundry {
        ProjectType::Foundry
    } else if hardhat {
        ProjectType::Hardhat
    } else if source_files.iter().any(|file| file.language == "solidity") {
        ProjectType::Solidity
    } else if source_files.iter().any(|file| file.language == "vyper") {
        ProjectType::Vyper
    } else {
        ProjectType::Unknown
    }
}

fn source_file(root: &Path, file: &Path, extension: &str) -> SatoriResult<SourceFile> {
    let bytes = std::fs::read(file)?;
    let language = match extension {
        "sol" => "solidity",
        "vy" => "vyper",
        other => other,
    }
    .to_string();
    Ok(SourceFile {
        path: file.to_path_buf(),
        relative_path: file.strip_prefix(root).unwrap_or(file).to_path_buf(),
        language,
        content_hash: sha256_hex(&bytes),
        bytes: bytes.len(),
        text: Some(read_lossy_limited(file, 128_000)?),
    })
}

fn is_doc_file(path: &PathBuf) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(name.as_str(), "readme.md" | "readme" | "readme.txt")
        || path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| matches!(ext, "md" | "rst" | "txt"))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn satori_ingests_fixture_sources() {
        let root = PathBuf::from("tests/fixtures/satori");
        let run_dir = std::env::temp_dir().join("satori-ingest-fixture-test");
        let _ = std::fs::remove_dir_all(&run_dir);
        let model = ingest_project(&root, &run_dir).unwrap();
        assert!(model.source_files.len() >= 4);
        assert!(run_dir.join("project.json").exists());
        let _ = std::fs::remove_dir_all(run_dir);
    }
}
