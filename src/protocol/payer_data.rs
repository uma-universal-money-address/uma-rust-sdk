use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::protocol::kyc_status::KycStatus;

use super::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayerData(pub Value);

impl PayerData {
    pub fn identifier(&self) -> Option<&str> {
        self.0.get("identifier").and_then(|v| v.as_str())
    }

    pub fn name(&self) -> Option<&str> {
        self.0.get("name").and_then(|v| v.as_str())
    }

    pub fn email(&self) -> Option<&str> {
        self.0.get("email").and_then(|v| v.as_str())
    }

    pub fn string_field(&self, field: &str) -> Option<&str> {
        self.0.get(field).and_then(|v| v.as_str())
    }

    pub fn compliance(&self) -> Result<CompliancePayerData, Error> {
        let compliance = self
            .0
            .get("compliance")
            .ok_or(Error::MissingPayerDataCompliance)?;
        let result: CompliancePayerData = serde_json::from_value(compliance.clone())
            .map_err(|_| Error::MissingPayerDataCompliance)?;
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TravelRuleFormat {
    pub type_field: Option<String>,

    pub value: Option<String>,
}

impl Serialize for TravelRuleFormat {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match (&self.type_field, &self.value) {
            (Some(type_field), Some(value)) => {
                serializer.serialize_str(&format!("{}@{}", type_field, value))
            }
            (None, Some(value)) => serializer.serialize_str(value),
            _ => serializer.serialize_none(),
        }
    }
}

impl<'de> Deserialize<'de> for TravelRuleFormat {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let parts: Vec<&str> = s.split('@').collect();
        match parts.len() {
            1 => Ok(TravelRuleFormat {
                type_field: None,
                value: Some(parts[0].to_string()),
            }),
            2 => Ok(TravelRuleFormat {
                type_field: Some(parts[0].to_string()),
                value: Some(parts[1].to_string()),
            }),
            _ => Err(serde::de::Error::custom("invalid travel rule format")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompliancePayerData {
    /// utxos is the list of UTXOs of the sender's channels that might be used to fund the payment.
    pub utxos: Vec<String>,

    /// node_pubkey is the public key of the sender's node if known.
    #[serde(rename = "nodePubkey")]
    pub node_pubkey: Option<String>,

    /// kyc_status indicates whether VASP1 has KYC information about the sender.
    #[serde(rename = "kycStatus")]
    pub kyc_status: KycStatus,

    /// encrypted_travel_rule_info is the travel rule information of the sender. This is encrypted
    /// with the receiver's public encryption key.
    #[serde(rename = "encryptedTravelRuleInfo")]
    pub encrypted_travel_rule_info: Option<String>,

    /// travel_rule_format is an optional standardized format of the travel rule information
    /// (e.g. IVMS). Null indicates raw json or a custom format. This field is formatted as
    /// <standardized format>@<version> (e.g. ivms@101.2023). Version is optional.
    #[serde(rename = "travelRuleFormat")]
    pub travel_rule_format: Option<TravelRuleFormat>,

    // signature is the hex-encoded signature of sha256(ReceiverAddress|Nonce|Timestamp).
    pub signature: String,

    #[serde(rename = "signatureNonce")]
    pub signature_nonce: String,

    #[serde(rename = "signatureTimestamp")]
    pub signature_timestamp: i64,

    /// UtxoCallback is the URL that the receiver will call to send UTXOs of the channel that the
    /// receiver used to receive the payment once it completes.
    #[serde(rename = "utxoCallback")]
    pub utxo_callback: String,
}
