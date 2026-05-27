use crate::satori::types::SourceFile;

pub fn summarize_docs(docs: &[SourceFile]) -> String {
    if docs.is_empty() {
        return "No docs or README files were collected.".to_string();
    }
    let names = docs
        .iter()
        .take(12)
        .map(|doc| doc.relative_path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("Collected {} documentation files: {names}", docs.len())
}
