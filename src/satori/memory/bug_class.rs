pub fn normalize_bug_class(input: &str) -> String {
    input.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}
