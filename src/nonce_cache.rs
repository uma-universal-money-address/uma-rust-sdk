use std::collections::HashMap;

use anyhow::anyhow;

pub trait NonceCache: Send + Sync {
    fn check_and_save_nonce(&mut self, nonce: &str, timestamp: i64) -> Result<(), anyhow::Error>;
    fn purge_nonce(&mut self, timestamp: i64);
}

pub struct InMemoryNonceCache {
    cache: HashMap<String, i64>,
    oldest_timestamp: i64,
}

impl InMemoryNonceCache {
    pub fn new(oldest_timestamp: i64) -> InMemoryNonceCache {
        InMemoryNonceCache {
            cache: HashMap::new(),
            oldest_timestamp,
        }
    }
}

impl NonceCache for InMemoryNonceCache {
    fn check_and_save_nonce(&mut self, nonce: &str, timestamp: i64) -> Result<(), anyhow::Error> {
        if timestamp < self.oldest_timestamp {
            return Err(anyhow!("Timestamp too old!"));
        }
        if self.cache.contains_key(nonce) {
            return Err(anyhow!("Nonce already used!"));
        }

        self.cache.insert(nonce.to_string(), timestamp);
        Ok(())
    }

    fn purge_nonce(&mut self, timestamp: i64) {
        let mut keys_to_remove = Vec::new();
        for (nonce, nonce_timestamp) in self.cache.iter() {
            if *nonce_timestamp < timestamp {
                keys_to_remove.push(nonce.clone());
            }
        }

        for key in keys_to_remove {
            self.cache.remove(&key);
        }
    }
}
