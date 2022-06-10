use super::Meta;
use std::{collections::BTreeSet, sync::Arc};

mod network;

pub use self::network::Network;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Authorization {
    pub networks: Vec<Network>,
    pub authentication: Authentication,
    pub meta: Arc<Meta>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Authentication {
    Unauthenticated,
    TlsUnauthenticated,
    TlsAuthenticated {
        identities: BTreeSet<String>,
        suffixes: Vec<Suffix>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Suffix {
    ends_with: String,
}

// === impl Suffix ===

impl From<Vec<String>> for Suffix {
    fn from(parts: Vec<String>) -> Self {
        let ends_with = if parts.is_empty() {
            "".to_string()
        } else {
            format!(".{}", parts.join("."))
        };
        Suffix { ends_with }
    }
}

impl Suffix {
    #[inline]
    pub fn contains(&self, name: &str) -> bool {
        name.ends_with(&self.ends_with)
    }
}