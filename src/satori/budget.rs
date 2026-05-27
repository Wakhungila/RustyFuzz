use crate::satori::types::BudgetReport;

#[derive(Debug, Clone, Default)]
pub struct BudgetTracker {
    report: BudgetReport,
}

impl BudgetTracker {
    pub fn record_call(&mut self, input: &str, output: &str, cached: bool) {
        if cached {
            self.report.cached_model_hits += 1;
        } else {
            self.report.model_calls += 1;
        }
        self.report.approximate_input_tokens += approximate_tokens(input);
        self.report.approximate_output_tokens += approximate_tokens(output);
    }

    pub fn note(&mut self, note: impl Into<String>) {
        self.report.notes.push(note.into());
    }

    pub fn report(&self) -> BudgetReport {
        self.report.clone()
    }
}

fn approximate_tokens(text: &str) -> usize {
    (text.len() / 4).max(text.split_whitespace().count())
}
