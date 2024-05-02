use serde::{Deserialize, Serialize};

use super::Error;

/// PostTransactionCallback is sent between VASPs after the payment is complete.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PostTransactionCallback {
    // Utxos is a list of utxo/amounts corresponding to the VASPs channels.
    utxos: Vec<UtxoWithAmount>,

    // VaspDomain is the domain of the VASP that is sending the callback.
    // It will be used by the VASP to fetch the public keys of its counterparty.
    #[serde(rename = "vaspDomain")]
    vasp_domain: Option<String>,

    // Signature is the base64-encoded signature of sha256(Nonce|Timestamp).
    signature: Option<String>,

    // Nonce is a random string that is used to prevent replay attacks.
    nonce: Option<String>,

    // Timestamp is the unix timestamp of when the request was sent. Used in the signature.
    timestamp: Option<i64>,
}

impl PostTransactionCallback {
    pub fn signable_payload(&self) -> Result<Vec<u8>, Error> {
        let timestamp = self.timestamp.ok_or(Error::MissingTimestamp)?;
        let nonce = self.nonce.as_deref().ok_or(Error::MissingNonce)?;
        let payload_string = format!("{}|{}", nonce, timestamp);
        Ok(payload_string.into_bytes())
    }
}

/// UtxoWithAmount is a pair of utxo and amount transferred over that corresponding channel.
/// It can be used to register payment for KYT.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UtxoWithAmount {
    /// utxo The utxo of the channel over which the payment went through in the format of
    /// <transaction_hash>:<output_index>.
    pub utxo: String,

    /// Amount The amount of funds transferred in the payment in mSats.
    #[serde(rename = "amountMsats")]
    pub amount: i64,
}
