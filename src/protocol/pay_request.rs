use serde::{Deserialize, Serialize};

use super::payer_data::PayerData;

/// PayRequest is the request sent by the sender to the receiver to retrieve an invoice.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PayRequest {
    /// currency_code is the ISO 3-digit currency code that the receiver will receive for this
    /// payment.
    #[serde(rename = "currencyCode")]
    pub currency_code: String,

    /// amount is the amount that the receiver will receive for this payment in the smallest unit of
    /// the specified currency (i.e. cents for USD).
    pub amount: i64,

    /// PayerData is the data that the sender will send to the receiver to identify themselves.
    #[serde(rename = "payerData")]
    pub payer_data: PayerData,
}

impl PayRequest {
    pub fn signable_payload(&self) -> Vec<u8> {
        let payload_string = format!(
            "{}|{}|{}",
            self.payer_data.identifier,
            self.payer_data.compliance.signature_nonce,
            self.payer_data.compliance.signature_timestamp,
        );
        payload_string.into_bytes()
    }
}
