use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FoundryHarnessManifest {
    pub project_root: PathBuf,
    pub files_scanned: Vec<PathBuf>,
    pub invariant_functions: Vec<FoundryInvariantFunction>,
    pub target_contracts: Vec<FoundryTargetContract>,
    pub target_selectors: Vec<FoundryTargetSelector>,
    pub handler_contracts: Vec<FoundryHandlerContract>,
    pub deployments: Vec<FoundryDeployment>,
    pub actors: Vec<FoundryActor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FoundryInvariantFunction {
    pub file: PathBuf,
    pub contract: Option<String>,
    pub name: String,
    pub visibility: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FoundryTargetContract {
    pub file: PathBuf,
    pub line: usize,
    pub expression: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FoundryTargetSelector {
    pub file: PathBuf,
    pub line: usize,
    pub target_expression: Option<String>,
    pub selectors: Vec<FoundrySelector>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FoundrySelector {
    pub expression: String,
    pub selector_hex: Option<[u8; 4]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FoundryHandlerContract {
    pub file: PathBuf,
    pub contract: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FoundryDeployment {
    pub file: PathBuf,
    pub line: usize,
    pub variable: Option<String>,
    pub contract: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FoundryActor {
    pub file: PathBuf,
    pub line: usize,
    pub expression: String,
}

impl FoundryHarnessManifest {
    pub fn ingest(project_root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let requested_root = project_root.as_ref();
        let root_metadata = fs::symlink_metadata(requested_root)?;
        anyhow::ensure!(
            !root_metadata.file_type().is_symlink(),
            "Solidity collection encountered a symlink entry at collection root: {}",
            requested_root.display()
        );
        let project_root = requested_root.canonicalize()?;
        let budgets = CollectionBudgets::default();
        let mut files = Vec::new();
        collect_solidity_files_with_budgets(&project_root, &mut files, budgets)?;
        files.sort();

        let mut manifest = Self {
            project_root: project_root.clone(),
            files_scanned: files.clone(),
            invariant_functions: Vec::new(),
            target_contracts: Vec::new(),
            target_selectors: Vec::new(),
            handler_contracts: Vec::new(),
            deployments: Vec::new(),
            actors: Vec::new(),
        };

        let mut total_bytes = 0u64;
        for file in files {
            let content = read_solidity_file(&project_root, &file, budgets, &mut total_bytes)?;
            let clean = strip_comments_preserve_lines(&content);
            manifest.ingest_file(&project_root, &file, &clean);
        }

        manifest.dedup_and_sort();
        Ok(manifest)
    }

    pub fn has_invariants(&self) -> bool {
        !self.invariant_functions.is_empty()
    }

    fn ingest_file(&mut self, root: &Path, file: &Path, content: &str) {
        let rel = file.strip_prefix(root).unwrap_or(file).to_path_buf();
        let mut current_contract: Option<String> = None;
        let mut statement = String::new();
        let mut statement_start = 1usize;

        for (line_idx, line) in content.lines().enumerate() {
            let line_no = line_idx + 1;
            let trimmed = line.trim();
            if statement.is_empty() {
                statement_start = line_no;
            }
            if !trimmed.is_empty() {
                statement.push(' ');
                statement.push_str(trimmed);
            }

            if let Some(contract) = parse_contract_name(trimmed) {
                if is_handler_contract(trimmed, &contract) {
                    self.handler_contracts.push(FoundryHandlerContract {
                        file: rel.clone(),
                        contract: contract.clone(),
                        line: line_no,
                    });
                }
                current_contract = Some(contract);
            }

            if let Some(function) = parse_function_signature(trimmed) {
                if is_invariant_function(&function.name) {
                    self.invariant_functions.push(FoundryInvariantFunction {
                        file: rel.clone(),
                        contract: current_contract.clone(),
                        name: function.name,
                        visibility: function.visibility,
                        line: line_no,
                    });
                }
            }

            for expression in extract_call_arguments(trimmed, "targetContract") {
                self.target_contracts.push(FoundryTargetContract {
                    file: rel.clone(),
                    line: line_no,
                    expression,
                });
            }

            for expression in extract_call_arguments(trimmed, "excludeContract") {
                self.target_contracts.push(FoundryTargetContract {
                    file: rel.clone(),
                    line: line_no,
                    expression: format!("exclude:{expression}"),
                });
            }

            if trimmed.contains("targetSelector") && trimmed.ends_with(';') {
                self.target_selectors.push(FoundryTargetSelector {
                    file: rel.clone(),
                    line: line_no,
                    target_expression: extract_named_arg(trimmed, "addr"),
                    selectors: extract_selectors(trimmed),
                });
            }

            if !statement.trim().is_empty()
                && (trimmed.ends_with(';') || trimmed.ends_with(");") || trimmed.ends_with("});"))
            {
                self.ingest_statement(&rel, statement_start, statement.trim());
                statement.clear();
            }

            if let Some(deployment) = parse_deployment(trimmed) {
                self.deployments.push(FoundryDeployment {
                    file: rel.clone(),
                    line: line_no,
                    variable: deployment.variable,
                    contract: deployment.contract,
                });
            }

            for actor in extract_actor_expressions(trimmed) {
                self.actors.push(FoundryActor {
                    file: rel.clone(),
                    line: line_no,
                    expression: actor,
                });
            }
        }
    }

    fn ingest_statement(&mut self, file: &Path, line: usize, statement: &str) {
        if statement.contains("targetSelector") {
            self.target_selectors.push(FoundryTargetSelector {
                file: file.to_path_buf(),
                line,
                target_expression: extract_named_arg(statement, "addr"),
                selectors: extract_selectors(statement),
            });
        }
    }

    fn dedup_and_sort(&mut self) {
        self.invariant_functions
            .sort_by(|a, b| (&a.file, a.line, &a.name).cmp(&(&b.file, b.line, &b.name)));
        self.target_contracts.sort_by(|a, b| {
            (&a.file, a.line, &a.expression).cmp(&(&b.file, b.line, &b.expression))
        });
        self.target_selectors
            .sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
        self.handler_contracts
            .sort_by(|a, b| (&a.file, a.line, &a.contract).cmp(&(&b.file, b.line, &b.contract)));
        self.deployments
            .sort_by(|a, b| (&a.file, a.line, &a.contract).cmp(&(&b.file, b.line, &b.contract)));
        self.actors.sort_by(|a, b| {
            (&a.file, a.line, &a.expression).cmp(&(&b.file, b.line, &b.expression))
        });

        self.invariant_functions.dedup();
        self.target_contracts.dedup();
        self.target_selectors.dedup();
        self.handler_contracts.dedup();
        self.deployments.dedup();
        self.actors.dedup();
    }
}

const MAX_SOLIDITY_TRAVERSAL_DEPTH: usize = 64;
const MAX_SOLIDITY_FILE_COUNT: usize = 10_000;
const MAX_SOLIDITY_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SOLIDITY_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct CollectionBudgets {
    max_depth: usize,
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
}

impl Default for CollectionBudgets {
    fn default() -> Self {
        Self {
            max_depth: MAX_SOLIDITY_TRAVERSAL_DEPTH,
            max_files: MAX_SOLIDITY_FILE_COUNT,
            max_file_bytes: MAX_SOLIDITY_FILE_BYTES,
            max_total_bytes: MAX_SOLIDITY_TOTAL_BYTES,
        }
    }
}

#[derive(Debug)]
struct ParsedFunction {
    name: String,
    visibility: Option<String>,
}

#[derive(Debug)]
struct ParsedDeployment {
    variable: Option<String>,
    contract: String,
}

fn collect_solidity_files_with_budgets(
    dir: &Path,
    files: &mut Vec<PathBuf>,
    budgets: CollectionBudgets,
) -> anyhow::Result<()> {
    let root_metadata = fs::symlink_metadata(dir)?;
    anyhow::ensure!(
        !root_metadata.file_type().is_symlink(),
        "Solidity collection encountered a symlink entry at collection root: {}",
        dir.display()
    );
    let canonical_root = ensure_canonical_containment(dir, dir)?;
    anyhow::ensure!(
        fs::symlink_metadata(&canonical_root)?.is_dir(),
        "Solidity collection root is not a directory: {}",
        canonical_root.display()
    );

    let mut pending = vec![(canonical_root.clone(), 0usize)];
    let mut file_count = 0usize;
    let mut total_bytes = 0u64;

    while let Some((current_dir, current_depth)) = pending.pop() {
        for entry in fs::read_dir(&current_dir).with_context(|| {
            format!(
                "failed to read Solidity collection directory: {}",
                current_dir.display()
            )
        })? {
            let entry = entry.with_context(|| {
                format!(
                    "failed to read Solidity collection entry in: {}",
                    current_dir.display()
                )
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).with_context(|| {
                format!(
                    "failed to inspect Solidity collection entry: {}",
                    path.display()
                )
            })?;
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "Solidity collection encountered a symlink entry: {}",
                path.display()
            );

            let name = entry.file_name();
            if name == "lib" || name == "node_modules" || name == "out" || name == "cache" {
                continue;
            }

            let canonical_path = ensure_canonical_containment(&canonical_root, &path)?;
            let canonical_metadata = fs::metadata(&canonical_path).with_context(|| {
                format!(
                    "failed to inspect canonical Solidity collection entry: {}",
                    path.display()
                )
            })?;

            if canonical_metadata.is_dir() {
                let next_depth = current_depth
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("Solidity collection depth budget exceeded"))?;
                anyhow::ensure!(
                    next_depth <= budgets.max_depth,
                    "Solidity collection depth budget exceeded: maximum depth is {} (entry: {})",
                    budgets.max_depth,
                    canonical_path.display()
                );
                pending.push((canonical_path, next_depth));
                continue;
            }

            if !canonical_path
                .extension()
                .is_some_and(|extension| extension == "sol")
            {
                continue;
            }

            anyhow::ensure!(
                canonical_metadata.is_file(),
                "Solidity collection entry is not a regular file: {}",
                canonical_path.display()
            );
            file_count = file_count
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("Solidity collection file-count budget exceeded"))?;
            anyhow::ensure!(
                file_count <= budgets.max_files,
                "Solidity collection file-count budget exceeded: maximum is {} files",
                budgets.max_files
            );

            let file_bytes = canonical_metadata.len();
            anyhow::ensure!(
                file_bytes <= budgets.max_file_bytes,
                "Solidity file exceeds the per-file byte budget: {} bytes exceeds {} (file: {})",
                file_bytes,
                budgets.max_file_bytes,
                canonical_path.display()
            );
            total_bytes = total_bytes
                .checked_add(file_bytes)
                .ok_or_else(|| anyhow::anyhow!("Solidity collection total-byte budget exceeded"))?;
            anyhow::ensure!(
                total_bytes <= budgets.max_total_bytes,
                "Solidity collection total-byte budget exceeded: {} bytes exceeds {}",
                total_bytes,
                budgets.max_total_bytes
            );

            files.push(canonical_path);
        }
    }

    Ok(())
}

fn ensure_canonical_containment(root: &Path, path: &Path) -> anyhow::Result<PathBuf> {
    let canonical_root = root.canonicalize()?;
    let canonical_path = path.canonicalize()?;
    anyhow::ensure!(
        canonical_path.starts_with(&canonical_root),
        "Solidity collection entry is outside the canonical Solidity collection root: {}",
        path.display()
    );
    Ok(canonical_path)
}

fn read_solidity_file(
    root: &Path,
    path: &Path,
    budgets: CollectionBudgets,
    total_bytes: &mut u64,
) -> anyhow::Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "Solidity collection encountered a symlink entry while reading: {}",
        path.display()
    );
    let canonical_path = ensure_canonical_containment(root, path)?;
    let file = fs::File::open(&canonical_path)?;
    let read_limit = budgets.max_file_bytes.saturating_add(1);
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read Solidity source file: {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= budgets.max_file_bytes,
        "Solidity file exceeds the per-file byte budget: {} (file: {})",
        bytes.len(),
        path.display()
    );

    *total_bytes = total_bytes.checked_add(bytes.len() as u64).ok_or_else(|| {
        anyhow::anyhow!("Solidity collection total-byte budget exceeded while reading")
    })?;
    anyhow::ensure!(
        *total_bytes <= budgets.max_total_bytes,
        "Solidity collection total-byte budget exceeded while reading: {} bytes exceeds {}",
        *total_bytes,
        budgets.max_total_bytes
    );

    String::from_utf8(bytes).with_context(|| {
        format!(
            "Solidity source file is not valid UTF-8: {}",
            path.display()
        )
    })
}

fn strip_comments_preserve_lines(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_block = false;
    while let Some(ch) = chars.next() {
        if in_block {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block = false;
                out.push(' ');
                out.push(' ');
            } else if ch == '\n' {
                out.push('\n');
            } else {
                out.push(' ');
            }
            continue;
        }

        if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block = true;
            out.push(' ');
            out.push(' ');
        } else if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            out.push(' ');
            out.push(' ');
            for next in chars.by_ref() {
                if next == '\n' {
                    out.push('\n');
                    break;
                }
                out.push(' ');
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn parse_contract_name(line: &str) -> Option<String> {
    let rest = line
        .strip_prefix("contract ")
        .or_else(|| line.strip_prefix("abstract contract "))?;
    rest.split(|ch: char| ch.is_whitespace() || ch == '{' || ch == '(')
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn is_handler_contract(line: &str, name: &str) -> bool {
    name.contains("Handler") || line.contains(" is Handler") || line.contains("BaseHandler")
}

fn parse_function_signature(line: &str) -> Option<ParsedFunction> {
    let start = line.find("function ")?;
    let rest = &line[start + "function ".len()..];
    let name = rest
        .split_once('(')
        .map(|(name, _)| name.trim())
        .filter(|name| !name.is_empty())?;
    let visibility = ["public", "external", "internal", "private"]
        .iter()
        .find(|visibility| line.contains(**visibility))
        .map(|visibility| (*visibility).to_string());
    Some(ParsedFunction {
        name: name.to_string(),
        visibility,
    })
}

fn is_invariant_function(name: &str) -> bool {
    name.starts_with("invariant")
        || name.starts_with("statefulFuzz")
        || name.starts_with("echidna_")
        || name.starts_with("property_")
}

fn extract_call_arguments(line: &str, name: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut rest = line;
    let pattern = format!("{name}(");
    while let Some(idx) = rest.find(&pattern) {
        let after = &rest[idx + pattern.len()..];
        if let Some((arg, consumed)) = read_balanced_until_close(after) {
            args.push(arg.trim().to_string());
            rest = &after[consumed..];
        } else {
            break;
        }
    }
    args
}

fn read_balanced_until_close(input: &str) -> Option<(String, usize)> {
    let mut depth = 0usize;
    let mut out = String::new();
    for (idx, ch) in input.char_indices() {
        match ch {
            '(' => {
                depth += 1;
                out.push(ch);
            }
            ')' if depth == 0 => return Some((out, idx + 1)),
            ')' => {
                depth -= 1;
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    None
}

fn extract_named_arg(line: &str, name: &str) -> Option<String> {
    let pattern = format!("{name}:");
    let start = line.find(&pattern)? + pattern.len();
    let rest = &line[start..];
    let mut expr = String::new();
    let mut depth = 0usize;
    for ch in rest.chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                expr.push(ch);
            }
            ')' | ']' | '}' if depth > 0 => {
                depth -= 1;
                expr.push(ch);
            }
            ',' | ')' | '}' if depth == 0 => break,
            _ => expr.push(ch),
        }
    }
    let expr = expr.trim();
    (!expr.is_empty()).then(|| expr.to_string())
}

fn extract_selectors(line: &str) -> Vec<FoundrySelector> {
    let mut selectors = BTreeSet::new();
    for token in line.split(|ch: char| ch.is_whitespace() || ch == ',' || ch == '[' || ch == ']') {
        let token = token.trim();
        if token.ends_with(".selector") || token.starts_with("bytes4(") {
            selectors.insert(token.trim_end_matches(';').to_string());
        }
        if let Some(hex) = parse_bytes4_literal(token) {
            selectors.insert(format!("0x{}", hex::encode(hex)));
        }
    }
    selectors
        .into_iter()
        .map(|expression| FoundrySelector {
            selector_hex: parse_selector_expression(&expression),
            expression,
        })
        .collect()
}

fn parse_selector_expression(expression: &str) -> Option<[u8; 4]> {
    if let Some(hex) = parse_bytes4_literal(expression) {
        return Some(hex);
    }
    if let Some(signature) = expression
        .strip_prefix("bytes4(keccak256(\"")
        .and_then(|rest| rest.split_once('"').map(|(sig, _)| sig))
    {
        return revm::primitives::keccak256(signature.as_bytes()).0[..4]
            .try_into()
            .ok();
    }
    None
}

fn parse_bytes4_literal(token: &str) -> Option<[u8; 4]> {
    let hex = token
        .trim_matches(|ch| ch == ')' || ch == ';')
        .strip_prefix("bytes4(0x")
        .or_else(|| token.strip_prefix("0x"))?;
    if hex.len() < 8 {
        return None;
    }
    let bytes = hex::decode(&hex[..8]).ok()?;
    bytes.try_into().ok()
}

fn parse_deployment(line: &str) -> Option<ParsedDeployment> {
    let new_idx = line.find("new ")?;
    let before = line[..new_idx].trim();
    let after = &line[new_idx + "new ".len()..];
    let contract = after
        .split(|ch: char| ch == '(' || ch.is_whitespace() || ch == ';')
        .next()
        .filter(|contract| !contract.is_empty())?;
    let variable = before
        .split('=')
        .next()
        .and_then(|left| left.split_whitespace().last())
        .filter(|var| !var.is_empty())
        .map(str::to_string);
    Some(ParsedDeployment {
        variable,
        contract: contract.to_string(),
    })
}

fn extract_actor_expressions(line: &str) -> Vec<String> {
    ["vm.prank", "vm.startPrank", "vm.deal", "boundActor"]
        .iter()
        .flat_map(|name| extract_call_arguments(line, name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingests_foundry_invariant_harness_metadata() {
        let root =
            std::env::temp_dir().join(format!("rusty_fuzz_foundry_ingest_{}", std::process::id()));
        let test_dir = root.join("test");
        std::fs::create_dir_all(&test_dir).expect("create test dir");
        std::fs::write(
            test_dir.join("VaultInvariant.t.sol"),
            r#"
pragma solidity ^0.8.24;

contract VaultHandler {
    function deposit(uint256 amount) external {}
}

contract VaultInvariantTest {
    VaultHandler handler;
    address alice = address(0xA11CE);

    function setUp() public {
        handler = new VaultHandler();
        targetContract(address(handler));
        targetSelector(FuzzSelector({
            addr: address(handler),
            selectors: selectors
        }));
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = VaultHandler.deposit.selector;
        selectors[1] = bytes4(keccak256("withdraw(uint256)"));
        vm.prank(alice);
    }

    function invariant_totalAssetsCoverShares() public {}
}
"#,
        )
        .expect("write harness");

        let manifest = FoundryHarnessManifest::ingest(&root).expect("ingest harness");
        assert!(manifest.has_invariants());
        assert_eq!(manifest.invariant_functions.len(), 1);
        assert_eq!(
            manifest.invariant_functions[0].name,
            "invariant_totalAssetsCoverShares"
        );
        assert_eq!(manifest.handler_contracts.len(), 1);
        assert_eq!(manifest.handler_contracts[0].contract, "VaultHandler");
        assert!(manifest
            .target_contracts
            .iter()
            .any(|target| target.expression == "address(handler)"));
        assert!(manifest
            .deployments
            .iter()
            .any(|deployment| deployment.contract == "VaultHandler"));
        assert!(manifest
            .actors
            .iter()
            .any(|actor| actor.expression == "alice"));
        assert!(manifest
            .target_selectors
            .iter()
            .any(|target| target.target_expression.as_deref() == Some("address(handler)")));
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "rusty_fuzz_foundry_{label}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            fs::create_dir_all(&path).expect("create test root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_budgets(
        max_depth: usize,
        max_files: usize,
        max_file_bytes: u64,
        max_total_bytes: u64,
    ) -> CollectionBudgets {
        CollectionBudgets {
            max_depth,
            max_files,
            max_file_bytes,
            max_total_bytes,
        }
    }

    fn collect_with_budgets(
        root: &Path,
        budgets: CollectionBudgets,
    ) -> anyhow::Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        collect_solidity_files_with_budgets(root, &mut files, budgets)?;
        Ok(files)
    }

    #[cfg(unix)]
    #[test]
    fn solidity_collection_rejects_symlink_file_entries() {
        let root = TestRoot::new("symlink_file");
        let outside = TestRoot::new("symlink_file_outside");
        fs::write(outside.path().join("Outside.sol"), "contract Outside {}")
            .expect("write outside");
        std::os::unix::fs::symlink(
            outside.path().join("Outside.sol"),
            root.path().join("Linked.sol"),
        )
        .expect("create file symlink");

        let error = collect_with_budgets(root.path(), test_budgets(4, 10, 1024, 4096))
            .expect_err("symlink entry must fail closed");

        assert!(error
            .to_string()
            .contains("Solidity collection encountered a symlink entry"));
    }

    #[cfg(unix)]
    #[test]
    fn solidity_collection_rejects_symlink_directory_entries() {
        let root = TestRoot::new("symlink_dir");
        let outside = TestRoot::new("symlink_dir_outside");
        std::os::unix::fs::symlink(outside.path(), root.path().join("linked"))
            .expect("create dir symlink");

        let error = collect_with_budgets(root.path(), test_budgets(4, 10, 1024, 4096))
            .expect_err("symlink directory must fail closed");

        assert!(error
            .to_string()
            .contains("Solidity collection encountered a symlink entry"));
    }

    #[cfg(unix)]
    #[test]
    fn solidity_collection_rejects_a_symlink_root() {
        let actual_root = TestRoot::new("symlink_root_actual");
        let link = actual_root.path().with_extension("linked");
        let _ = fs::remove_dir_all(&link);
        std::os::unix::fs::symlink(actual_root.path(), &link).expect("create root symlink");

        let error = collect_with_budgets(&link, test_budgets(4, 10, 1024, 4096))
            .expect_err("symlink collection root must fail closed");

        assert!(error
            .to_string()
            .contains("Solidity collection encountered a symlink entry"));
        let _ = fs::remove_file(&link);
    }

    #[test]
    fn solidity_collection_rejects_paths_outside_the_canonical_root() {
        let root = TestRoot::new("containment_root");
        let outside = TestRoot::new("containment_outside");
        let outside_file = outside.path().join("Outside.sol");
        fs::write(&outside_file, "contract Outside {}").expect("write outside file");

        let error = ensure_canonical_containment(root.path(), &outside_file)
            .expect_err("outside canonical path must fail closed");

        assert!(error
            .to_string()
            .contains("outside the canonical Solidity collection root"));
    }

    #[test]
    fn solidity_collection_enforces_depth_budget() {
        let root = TestRoot::new("depth");
        fs::create_dir_all(root.path().join("one/two")).expect("create nested directories");
        fs::write(root.path().join("one/two/Deep.sol"), "contract Deep {}")
            .expect("write nested Solidity");

        let error = collect_with_budgets(root.path(), test_budgets(1, 10, 1024, 4096))
            .expect_err("depth budget must fail closed");

        assert!(error
            .to_string()
            .contains("Solidity collection depth budget exceeded"));
    }

    #[test]
    fn solidity_collection_enforces_file_count_budget() {
        let root = TestRoot::new("file_count");
        fs::write(root.path().join("One.sol"), "contract One {}").expect("write first file");
        fs::write(root.path().join("Two.sol"), "contract Two {}").expect("write second file");

        let error = collect_with_budgets(root.path(), test_budgets(4, 1, 1024, 4096))
            .expect_err("file-count budget must fail closed");

        assert!(error
            .to_string()
            .contains("Solidity collection file-count budget exceeded"));
    }

    #[test]
    fn solidity_collection_enforces_per_file_byte_budget() {
        let root = TestRoot::new("file_bytes");
        fs::write(root.path().join("Large.sol"), vec![b'x'; 9]).expect("write oversized file");

        let error = collect_with_budgets(root.path(), test_budgets(4, 10, 8, 4096))
            .expect_err("per-file budget must fail closed");

        assert!(error
            .to_string()
            .contains("Solidity file exceeds the per-file byte budget"));
    }

    #[test]
    fn solidity_collection_enforces_total_byte_budget() {
        let root = TestRoot::new("total_bytes");
        fs::write(root.path().join("One.sol"), vec![b'a'; 4]).expect("write first file");
        fs::write(root.path().join("Two.sol"), vec![b'b'; 4]).expect("write second file");

        let error = collect_with_budgets(root.path(), test_budgets(4, 10, 5, 7))
            .expect_err("total-byte budget must fail closed");

        assert!(error
            .to_string()
            .contains("Solidity collection total-byte budget exceeded"));
    }

    #[test]
    fn solidity_collection_accepts_exact_budget_boundaries() {
        let root = TestRoot::new("boundaries");
        fs::create_dir_all(root.path().join("nested")).expect("create nested directory");
        fs::write(root.path().join("nested/One.sol"), vec![b'a'; 3]).expect("write first file");
        fs::write(root.path().join("Two.sol"), vec![b'b'; 3]).expect("write second file");

        let files = collect_with_budgets(root.path(), test_budgets(1, 2, 3, 6))
            .expect("exact budgets must be accepted");

        assert_eq!(files.len(), 2);
    }

    #[test]
    fn parses_bytes4_keccak_selector_expression() {
        let selector = parse_selector_expression(r#"bytes4(keccak256("withdraw(uint256)"))"#)
            .expect("selector");
        let expected: [u8; 4] = revm::primitives::keccak256("withdraw(uint256)".as_bytes()).0[..4]
            .try_into()
            .unwrap();
        assert_eq!(selector, expected);
    }
}
