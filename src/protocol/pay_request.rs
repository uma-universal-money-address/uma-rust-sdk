use serde::{Deserialize, Serialize};

use super::{counter_party_data::CounterPartyDataOptions, payer_data::PayerData, Error};

/// PayRequest is the request sent by the sender to the receiver to retrieve an invoice.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PayRequest {
    // SendingAmountCurrencyCode is the currency code of the `amount` field. `nil` indicates that `amount` is in
    // millisatoshis as in LNURL without LUD-21. If this is not `nil`, then `amount` is in the smallest unit of the
    // specified currency (e.g. cents for USD). This currency code can be any currency which the receiver can quote.
    // However, there are two most common scenarios for UMA:
    //
    // 1. If the sender wants the receiver wants to receive a specific amount in their receiving
    // currency, then this field should be the same as `receiving_currency_code`. This is useful
    // for cases where the sender wants to ensure that the receiver receives a specific amount
    // in that destination currency, regardless of the exchange rate, for example, when paying
    // for some goods or services in a foreign currency.
    //
    // 2. If the sender has a specific amount in their own currency that they would like to send,
    // then this field should be left as `None` to indicate that the amount is in millisatoshis.
    // This will lock the sent amount on the sender side, and the receiver will receive the
    // equivalent amount in their receiving currency. NOTE: In this scenario, the sending VASP
    // *should not* pass the sending currency code here, as it is not relevant to the receiver.
    // Rather, by specifying an invoice amount in msats, the sending VASP can ensure that their
    // user will be sending a fixed amount, regardless of the exchange rate on the receiving side.
    #[serde(rename = "sendingAmountCurrencyCode")]
    pub sending_amount_currency_code: Option<String>,

    // ReceivingCurrencyCode is the ISO 3-digit currency code that the receiver will receive for this payment. Defaults
    // to amount being specified in msats if this is not provided.
    #[serde(rename = "receivingCurrencyCode")]
    pub receiving_currency_code: Option<String>,

    // Amount is the amount that the receiver will receive for this payment in the smallest unit of the specified
    // currency (i.e. cents for USD) if `SendingAmountCurrencyCode` is not `nil`. Otherwise, it is the amount in
    // millisatoshis.
    pub amount: i64,

    // PayerData is the data that the sender will send to the receiver to identify themselves. Required for UMA, as is
    // the `compliance` field in the `payerData` object.
    #[serde(rename = "payerData")]
    pub payer_data: Option<PayerData>,

    // RequestedPayeeData is the data that the sender is requesting about the payee.
    #[serde(rename = "payeeData")]
    pub requested_payee_data: Option<CounterPartyDataOptions>,

    // Comment is a comment that the sender would like to include with the payment. This can only be included
    // if the receiver included the `commentAllowed` field in the lnurlp response. The length of
    // the comment must be less than or equal to the value of `commentAllowed`.
    pub comment: Option<String>,

    // UmaMajorVersion is the major version of the UMA protocol that the VASP supports for this currency. This is used
    // for serialization, but is not serialized itself.
    pub uma_major_version: i32,
}

impl PayRequest {
    pub fn signable_payload(&self) -> Result<Vec<u8>, Error> {
        let payer_data = self.payer_data.clone().ok_or(Error::MissingNonce)?;
        let sender_address = payer_data
            .identifier()
            .ok_or(Error::MissingPayerDataIdentifier)?;

        let compliance_data = payer_data
            .compliance()?
            .ok_or(Error::MissingPayerDataCompliance)?;

        let payload_string = format!(
            "{}|{}|{}",
            sender_address, compliance_data.signature_nonce, compliance_data.signature_timestamp,
        );
        Ok(payload_string.into_bytes())
    }

    pub fn is_uma_request(&self) -> bool {
        if let Some(payer_data) = &self.payer_data {
            if let Ok(compliance) = payer_data.compliance() {
                return compliance.is_some() && payer_data.identifier().is_some();
            }
        }
        false
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PayRequestV0 {
    #[serde(rename = "currency")]
    receiving_currency_code: Option<String>,
    amount: i64,
    payer_data: Option<PayerData>,
    #[serde(rename = "payeeData")]
    requested_payee_data: Option<CounterPartyDataOptions>,
    comment: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PayRequestV1 {
    #[serde(rename = "currency")]
    receiving_currency_code: Option<String>,
    amount: i64,
    payer_data: Option<PayerData>,
    #[serde(rename = "payeeData")]
    requested_payee_data: Option<CounterPartyDataOptions>,
    comment: Option<String>,
}
