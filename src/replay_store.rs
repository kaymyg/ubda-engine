use std::collections::HashSet;

pub struct ReplayStore {
    seen_capabilities: HashSet<String>,
    seen_nonces: HashSet<(String, u64)>,
}

impl ReplayStore {
    pub fn new() -> Self {
        Self {
            seen_capabilities: HashSet::new(),
            seen_nonces: HashSet::new(),
        }
    }

    pub fn check_and_register(&mut self, cap_id: &str, session_id: &str, nonce: u64) -> bool {
        if self.seen_capabilities.contains(cap_id) {
            return false;
        }
        if self.seen_nonces.contains(&(session_id.to_string(), nonce)) {
            return false;
        }

        self.seen_capabilities.insert(cap_id.to_string());
        self.seen_nonces.insert((session_id.to_string(), nonce));
        true
    }
}

impl Default for ReplayStore {
    fn default() -> Self {
        Self::new()
    }
}
