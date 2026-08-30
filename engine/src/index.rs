use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub struct ThreatIndex {
    pub logs: Vec<String>,
    index: HashMap<String, Vec<usize>>,
}

impl ThreatIndex {
    fn tokenize(log: &str) -> HashSet<String> {
        let mut tokens = HashSet::new();
        for word in log.split_whitespace() {
            let lower = word.to_lowercase();

            // Always store the full word if it contains at least one alphanumeric character.
            if lower.chars().any(|c| c.is_alphanumeric()) {
                tokens.insert(lower.clone());
            }

            // Split on any non-alphanumeric character and add meaningful sub-tokens.
            for sub in lower.split(|c: char| !c.is_alphanumeric()) {
                if !sub.is_empty() && sub.chars().any(|c| c.is_alphanumeric()) {
                    tokens.insert(sub.to_string());
                }
            }
        }
        tokens
    }

    pub fn add_threat(&mut self, log: String) {
        let idx = self.logs.len();
        self.logs.push(log.clone());

        // Tokenize and index
        for token in ThreatIndex::tokenize(&log) {
            self.index.entry(token).or_default().push(idx); //or default is mnmore ididmatic,
            //so use that
        }
    }

    pub fn search_by_token(&self, term: &str) -> Vec<&String> {
        let term = term.to_lowercase();
        self.index
            .get(&term)
            .map(|indices| indices.iter().map(|&i| &self.logs[i]).collect())
            .unwrap_or_default()
    }
}
