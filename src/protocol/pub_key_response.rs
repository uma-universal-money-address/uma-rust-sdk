use serde::{Deserialize, Serialize};

/// PubKeyResponse is sent from a VASP to another VASP to provide its public keys.
/// It is the response to GET requests at `/.well-known/lnurlpubkey`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PubKeyResponse {
    /// signing_pub_key is used to verify signatures from a VASP.
    #[serde(rename = "signingPubKey")]
    pub signing_pub_key: Vec<u8>,

    // encryption_pub_key is used to encrypt TR info sent to a VASP.
    #[serde(rename = "encryptionPubKey")]
    pub encryption_pub_key: Vec<u8>,

    // expiration_timestamp [Optional] Seconds since epoch at which these pub keys must be refreshed.
    // They can be safely cached until this expiration (or forever if null).
    #[serde(rename = "expirationTimestamp")]
    pub expiration_timestamp: Option<i64>,
}
