use serde::{Deserialize, Serialize};

use super::Error;

/// PostTransactionCallback is sent between VASPs after the payment is complete.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PostTransactionCallback {
    // Utxos is a list of utxo/amounts corresponding to the VASPs channels.
    pub utxos: Vec<UtxoWithAmount>,

    // VaspDomain is the domain of the VASP that is sending the callback.
    // It will be used by the VASP to fetch the public keys of its counterparty.
    #[serde(rename = "vaspDomain")]
    pub vasp_domain: Option<String>,

    // Signature is the base64-encoded signature of sha256(Nonce|Timestamp).
    pub signature: Option<String>,

    // Nonce is a random string that is used to prevent replay attacks.
    pub nonce: Option<String>,

    // Timestamp is the unix timestamp of when the request was sent. Used in the signature.
    pub timestamp: Option<i64>,
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

#[derive(Default)]
pub struct PostTransactionCallbackBuilder {
    utxos: Vec<UtxoWithAmount>,
    vasp_domain: Option<String>,
    signature: Option<String>,
    nonce: Option<String>,
    timestamp: Option<i64>,
}

impl PostTransactionCallbackBuilder {
    pub fn utxos(mut self, utxos: Vec<UtxoWithAmount>) -> Self {
        self.utxos = utxos;
        self
    }

    pub fn vasp_domain(mut self, vasp_domain: String) -> Self {
        self.vasp_domain = Some(vasp_domain);
        self
    }

    pub fn signature(mut self, signature: String) -> Self {
        self.signature = Some(signature);
        self
    }

    pub fn nonce(mut self, nonce: String) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn timestamp(mut self, timestamp: i64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn build(&self) -> PostTransactionCallback {
        PostTransactionCallback {
            utxos: self.utxos.clone(),
            vasp_domain: self.vasp_domain.clone(),
            signature: self.signature.clone(),
            nonce: self.nonce.clone(),
            timestamp: self.timestamp,
        }
    }
}
