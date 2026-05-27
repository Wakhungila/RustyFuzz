use std::path::Path;

pub fn is_hardhat_project(root: &Path) -> bool {
    root.join("hardhat.config.js").exists()
        || root.join("hardhat.config.ts").exists()
        || root.join("package.json").exists()
}
