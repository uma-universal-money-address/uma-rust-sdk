use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayeeData(pub Value);

impl PayeeData {
    pub fn compliance(&self) -> Result<Option<CompliancePayeeData>, Error> {
        if let Some(compliance) = self.0.get("compliance") {
            let result: CompliancePayeeData = serde_json::from_value(compliance.clone())
                .map_err(|_| Error::MissingPayerDataCompliance)?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompliancePayeeData {
    /// NodePubKey is the public key of the receiver's node if known.
    #[serde(rename = "nodePubKey")]
    pub node_pubkey: Option<String>,

    // Utxos is a list of UTXOs of channels over which the receiver will likely receive the payment.
    pub utxos: Vec<String>,

    // UtxoCallback is the URL that the sender VASP will call to send UTXOs of the channel that the sender used to send the payment once it completes.
    #[serde(rename = "utxoCallback")]
    pub utxo_callback: Option<String>,

    // Signature is the base64-encoded signature of sha256(SenderAddress|ReceiverAddress|Nonce|Timestamp).
    // Note: This field is optional for UMA v0.X backwards-compatibility. It is required for UMA v1.X.
    pub signature: Option<String>,

    // SignatureNonce is a random string that is used to prevent replay attacks.
    // Note: This field is optional for UMA v0.X backwards-compatibility. It is required for UMA v1.X.
    #[serde(rename = "signatureNonce")]
    pub signature_nonce: Option<String>,

    // SignatureTimestamp is the unix timestamp (in seconds since epoch) of when the request was sent. Used in the signature.
    // Note: This field is optional for UMA v0.X backwards-compatibility. It is required for UMA v1.X.
    #[serde(rename = "signatureTimestamp")]
    pub signature_timestamp: Option<i64>,
}

impl CompliancePayeeData {
    pub fn signable_payload(
        &self,
        sender_address: &str,
        receiver_address: &str,
    ) -> Result<Vec<u8>, Error> {
        let nonce = self.signature_nonce.as_deref().ok_or(Error::MissingNonce)?;
        let timestamp = self.signature_timestamp.ok_or(Error::MissingTimestamp)?;
        let payload_string = format!(
            "{}|{}|{}|{}",
            sender_address, receiver_address, nonce, timestamp,
        );
        Ok(payload_string.into_bytes())
    }
}

pub struct CompliancePayeeDataBuilder {
    node_pubkey: Option<String>,
    utxos: Vec<String>,
    utxo_callback: Option<String>,
    signature: Option<String>,
    signature_nonce: Option<String>,
    signature_timestamp: Option<i64>,
}

impl CompliancePayeeDataBuilder {
    pub fn new() -> Self {
        Self {
            node_pubkey: None,
            utxos: Vec::new(),
            utxo_callback: None,
            signature: None,
            signature_nonce: None,
            signature_timestamp: None,
        }
    }

    pub fn node_pubkey(mut self, node_pubkey: Option<String>) -> Self {
        self.node_pubkey = node_pubkey;
        self
    }

    pub fn utxos(mut self, utxos: Vec<String>) -> Self {
        self.utxos = utxos;
        self
    }

    pub fn utxo_callback(mut self, utxo_callback: Option<String>) -> Self {
        self.utxo_callback = utxo_callback;
        self
    }

    pub fn signature(mut self, signature: Option<String>) -> Self {
        self.signature = signature;
        self
    }

    pub fn signature_nonce(mut self, signature_nonce: Option<String>) -> Self {
        self.signature_nonce = signature_nonce;
        self
    }

    pub fn signature_timestamp(mut self, signature_timestamp: Option<i64>) -> Self {
        self.signature_timestamp = signature_timestamp;
        self
    }

    pub fn build(&self) -> CompliancePayeeData {
        CompliancePayeeData {
            node_pubkey: self.node_pubkey.clone(),
            utxos: self.utxos.clone(),
            utxo_callback: self.utxo_callback.clone(),
            signature: self.signature.clone(),
            signature_nonce: self.signature_nonce.clone(),
            signature_timestamp: self.signature_timestamp.clone(),
        }
    }
}
