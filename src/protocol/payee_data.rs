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
