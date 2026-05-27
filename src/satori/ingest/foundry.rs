use std::path::Path;

pub fn is_foundry_project(root: &Path) -> bool {
    root.join("foundry.toml").exists()
}
