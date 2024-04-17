use serde::{Deserialize, Serialize};

use super::{currency::Currency, kyc_status::KycStatus, payer_data::PayerDataOptions};

/// LnurlpResponse is the response to the LnurlpRequest.
/// It is sent by the VASP that is receiving the payment to provide information to the sender about the receiver.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LnurlpResponse {
    pub tag: String,
    pub callback: String,

    #[serde(rename = "minSendable")]
    pub min_sendable: i64,

    #[serde(rename = "maxSendable")]
    pub max_sendable: i64,

    #[serde(rename = "metadata")]
    pub encoded_metadata: String,

    pub currencies: Vec<Currency>,

    #[serde(rename = "payerData")]
    pub required_payer_data: PayerDataOptions,

    pub compliance: LnurlComplianceResponse,

    /// UmaVersion is the version of the UMA protocol that VASP2 has chosen for this transaction
    /// based on its own support and VASP1's specified preference in the LnurlpRequest. For the
    /// version negotiation flow, see
    /// https://static.swimlanes.io/87f5d188e080cb8e0494e46f80f2ae74.png
    #[serde(rename = "umaVersion")]
    pub uma_version: String,
}

/// LnurlComplianceResponse is the `compliance` field  of the LnurlpResponse.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LnurlComplianceResponse {
    /// kyc_status indicates whether VASP2 has KYC information about the receiver.
    #[serde(rename = "kycStatus")]
    pub kyc_status: KycStatus,

    /// signature is the hex-encoded signature of sha256(ReceiverAddress|Nonce|Timestamp).
    pub signature: String,

    /// nonce is a random string that is used to prevent replay attacks.
    #[serde(rename = "signatureNonce")]
    pub nonce: String,

    /// timestamp is the unix timestamp of when the request was sent. Used in the signature.
    #[serde(rename = "signatureTimestamp")]
    pub timestamp: i64,

    /// is_subject_to_travel_rule indicates whether VASP2 is a financial institution that requires travel rule information.
    #[serde(rename = "isSubjectToTravelRule")]
    pub is_subject_to_travel_rule: bool,

    /// receiver_identifier is the identifier of the receiver at VASP2.
    #[serde(rename = "receiverIdentifier")]
    pub receiver_identifier: String,
}

impl LnurlpResponse {
    pub fn signable_payload(&self) -> Vec<u8> {
        let payload_string = format!(
            "{}|{}|{}",
            self.compliance.receiver_identifier, self.compliance.nonce, self.compliance.timestamp
        );
        payload_string.into_bytes()
    }
}
