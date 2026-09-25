use crate::models::{MetricSample, MetricType};

pub fn render(samples: &[MetricSample]) -> Result<String, crate::error::OperationsError> {
    let mut names = Vec::new();
    for sample in samples {
        if !valid_metric_name(&sample.name) {
            return Err(crate::error::OperationsError::InvalidData(
                "metric name is not a valid Prometheus identifier".to_string(),
            ));
        }
        names.push(sample.name.clone());
    }
    names.sort();
    names.dedup();
    let mut output = String::new();
    for name in names {
        let group: Vec<&MetricSample> = samples
            .iter()
            .filter(|sample| sample.name == name)
            .collect();
        let first = group[0];
        output.push_str("# HELP ");
        output.push_str(&name);
        output.push(' ');
        output.push_str(&escape_help(&first.help));
        output.push('\n');
        output.push_str("# TYPE ");
        output.push_str(&name);
        output.push(' ');
        output.push_str(match first.metric_type {
            MetricType::Counter => "counter",
            MetricType::Gauge => "gauge",
        });
        output.push('\n');
        for sample in group {
            output.push_str(&name);
            if !sample.labels.is_empty() {
                output.push('{');
                for (index, (key, value)) in sample.labels.iter().enumerate() {
                    if !valid_label_name(key) {
                        return Err(crate::error::OperationsError::InvalidData(
                            "metric label name is not valid".to_string(),
                        ));
                    }
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(key);
                    output.push_str("=\"");
                    output.push_str(&escape_label(value));
                    output.push('"');
                }
                output.push('}');
            }
            output.push(' ');
            if !sample.value.is_finite() {
                return Err(crate::error::OperationsError::InvalidData(
                    "metric value must be finite".to_string(),
                ));
            }
            if sample.value == sample.value.trunc() {
                output.push_str(&format!("{}", sample.value as i64));
            } else {
                output.push_str(&format!("{}", sample.value));
            }
            output.push('\n');
        }
    }
    Ok(output)
}

fn valid_metric_name(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|character| character.is_ascii_alphanumeric() || character == '_' || character == ':')
}

fn valid_label_name(value: &str) -> bool {
    valid_metric_name(value)
}

fn escape_help(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n")
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
