use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{
    collect_files, read_lossy_limited, redact_source_text, write_json_in_run,
};
use crate::satori::ingest::foundry::is_foundry_project;
use crate::satori::ingest::hardhat::is_hardhat_project;
use crate::satori::types::{ProjectModel, ProjectType, ProtocolType, SourceFile};
use std::path::Path;

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
    write_json_in_run(run_dir, Path::new("project.json"), &model)?;
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
    let metadata = std::fs::symlink_metadata(file)?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink() && metadata.is_file(),
        "Satori project file is not a regular canonical file: {}",
        file.display()
    );
    let canonical_file = file.canonicalize()?;
    anyhow::ensure!(
        canonical_file.starts_with(root),
        "Satori project file is outside canonical project root: {}",
        file.display()
    );
    let metadata = std::fs::metadata(&canonical_file)?;
    anyhow::ensure!(
        metadata.len() <= crate::satori::fsutil::MAX_INGEST_FILE_BYTES,
        "Satori project file exceeds the ingestion file-byte budget: {}",
        file.display()
    );
    let (content_hash, bytes) = hash_file(&canonical_file)?;
    let language = match extension {
        "sol" => "solidity",
        "vy" => "vyper",
        other => other,
    }
    .to_string();
    Ok(SourceFile {
        relative_path: canonical_file
            .strip_prefix(root)
            .map_err(|_| anyhow::anyhow!("Satori project file is outside canonical project root"))?
            .to_path_buf(),
        path: canonical_file.clone(),
        language,
        content_hash,
        bytes,
        text: Some(redact_source_text(&read_lossy_limited(
            &canonical_file,
            128_000,
        )?)),
    })
}

fn hash_file(path: &Path) -> SatoriResult<(String, usize)> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    let mut bytes = 0usize;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read)
            .ok_or_else(|| anyhow::anyhow!("Satori project byte budget overflow"))?;
        anyhow::ensure!(
            bytes as u64 <= crate::satori::fsutil::MAX_INGEST_FILE_BYTES,
            "Satori project file exceeds the ingestion file-byte budget"
        );
        hasher.update(&buffer[..read]);
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

fn is_doc_file(path: &Path) -> bool {
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
    use std::path::PathBuf;

    #[test]
    fn satori_ingests_fixture_sources() {
        let root = PathBuf::from("tests/fixtures/satori");
        let run_dir = crate::satori::fsutil::canonical_run_root()
            .unwrap()
            .join("satori-ingest-fixture-test");
        let _ = std::fs::remove_dir_all(&run_dir);
        std::fs::create_dir_all(&run_dir).unwrap();
        let model = ingest_project(&root, &run_dir).unwrap();
        assert!(model.source_files.len() >= 4);
        assert!(run_dir.join("project.json").exists());
        let _ = std::fs::remove_dir_all(run_dir);
    }

    #[test]
    fn project_artifact_omits_raw_source_text() -> SatoriResult<()> {
        let root = std::env::temp_dir().join(format!(
            "satori-ingest-redaction-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let run_dir = crate::satori::fsutil::canonical_run_root()?.join(format!(
            "satori-ingest-redaction-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(&run_dir)?;
        std::fs::write(
            root.join("Vault.sol"),
            b"contract Vault { function deposit() external { string private_key = \"raw-source-secret\"; } }",
        )?;

        let model = ingest_project(&root, &run_dir)?;
        let persisted = std::fs::read_to_string(run_dir.join("project.json"))?;
        assert!(!model.source_files[0]
            .text
            .as_deref()
            .is_some_and(|text| text.contains("raw-source-secret")));
        assert!(!persisted.contains("raw-source-secret"));

        let _ = std::fs::remove_dir_all(run_dir);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn satori_ingestion_rejects_symlink_entries() {
        let root = std::env::temp_dir().join(format!(
            "satori-ingest-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let run_dir = root.join("run");
        let outside = root.parent().unwrap().join(format!(
            "satori-outside-{}.sol",
            root.file_name().unwrap().to_string_lossy()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("Contract.sol"), b"contract Contract {}").unwrap();
        std::fs::write(&outside, b"contract Outside {}").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("Linked.sol")).unwrap();
        let result = ingest_project(&root, &run_dir);
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(outside);
    }
}
