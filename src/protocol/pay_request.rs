use serde::{Deserialize, Serialize};

use super::{counter_party_data::CounterPartyDataOptions, payer_data::PayerData, Error};

/// PayRequest is the request sent by the sender to the receiver to retrieve an invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub sending_amount_currency_code: Option<String>,

    // ReceivingCurrencyCode is the ISO 3-digit currency code that the receiver will receive for this payment. Defaults
    // to amount being specified in msats if this is not provided.
    pub receiving_currency_code: Option<String>,

    // Amount is the amount that the receiver will receive for this payment in the smallest unit of the specified
    // currency (i.e. cents for USD) if `SendingAmountCurrencyCode` is not `nil`. Otherwise, it is the amount in
    // millisatoshis.
    pub amount: i64,

    // PayerData is the data that the sender will send to the receiver to identify themselves. Required for UMA, as is
    // the `compliance` field in the `payerData` object.
    pub payer_data: Option<PayerData>,

    // RequestedPayeeData is the data that the sender is requesting about the payee.
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

pub struct PayRequestBuilder {
    sending_amount_currency_code: Option<String>,
    receiving_currency_code: Option<String>,
    amount: i64,
    payer_data: Option<PayerData>,
    requested_payee_data: Option<CounterPartyDataOptions>,
    comment: Option<String>,
    uma_major_version: i32,
}

impl Default for PayRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PayRequestBuilder {
    pub fn new() -> Self {
        Self {
            sending_amount_currency_code: None,
            receiving_currency_code: None,
            amount: 0,
            payer_data: None,
            requested_payee_data: None,
            comment: None,
            uma_major_version: 0,
        }
    }

    pub fn with_sending_amount_currency_code(
        mut self,
        sending_amount_currency_code: Option<String>,
    ) -> Self {
        self.sending_amount_currency_code = sending_amount_currency_code;
        self
    }

    pub fn with_receiving_currency_code(mut self, receiving_currency_code: Option<String>) -> Self {
        self.receiving_currency_code = receiving_currency_code;
        self
    }

    pub fn with_amount(mut self, amount: i64) -> Self {
        self.amount = amount;
        self
    }

    pub fn with_payer_data(mut self, payer_data: Option<PayerData>) -> Self {
        self.payer_data = payer_data;
        self
    }

    pub fn with_requested_payee_data(
        mut self,
        requested_payee_data: Option<CounterPartyDataOptions>,
    ) -> Self {
        self.requested_payee_data = requested_payee_data;
        self
    }

    pub fn with_comment(mut self, comment: Option<String>) -> Self {
        self.comment = comment;
        self
    }

    pub fn with_uma_major_version(mut self, uma_major_version: i32) -> Self {
        self.uma_major_version = uma_major_version;
        self
    }

    pub fn build(self) -> PayRequest {
        PayRequest {
            sending_amount_currency_code: self.sending_amount_currency_code,
            receiving_currency_code: self.receiving_currency_code,
            amount: self.amount,
            payer_data: self.payer_data,
            requested_payee_data: self.requested_payee_data,
            comment: self.comment,
            uma_major_version: self.uma_major_version,
        }
    }
}

impl Serialize for PayRequest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.uma_major_version == 0 {
            let pay_request_v0 = PayRequestV0 {
                receiving_currency_code: self.receiving_currency_code.clone(),
                amount: self.amount,
                payer_data: self.payer_data.clone(),
                requested_payee_data: self.requested_payee_data.clone(),
                comment: self.comment.clone(),
            };
            pay_request_v0.serialize(serializer)
        } else {
            let mut amount_str = self.amount.to_string();
            if let Some(currency_code) = &self.sending_amount_currency_code {
                amount_str = format!("{}.{}", amount_str, currency_code);
            }
            let pay_request_v1 = PayRequestV1 {
                receiving_currency_code: self.receiving_currency_code.clone(),
                amount: amount_str,
                payer_data: self.payer_data.clone(),
                requested_payee_data: self.requested_payee_data.clone(),
                comment: self.comment.clone(),
            };
            pay_request_v1.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for PayRequest {
    fn deserialize<D>(deserializer: D) -> Result<PayRequest, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};

        struct PayRequestVisitor;

        impl<'de> Visitor<'de> for PayRequestVisitor {
            type Value = PayRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a PayRequest")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut builder = PayRequestBuilder::new();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "currency" => {
                            let receiving_currency_code = map.next_value()?;
                            builder = builder
                                .with_receiving_currency_code(Some(receiving_currency_code))
                                .with_uma_major_version(0);
                        }
                        "convert" => {
                            let receiving_currency_code = map.next_value()?;
                            builder = builder
                                .with_receiving_currency_code(Some(receiving_currency_code))
                                .with_uma_major_version(1);
                        }
                        "amount" => {
                            let value = map.next_value()?;
                            match value {
                                serde_json::Value::String(s) => {
                                    if s.contains('.') {
                                        // handle decimal amount case
                                        let parts: Vec<&str> = s.split('.').collect();
                                        if parts.len() != 2 {
                                            return Err(serde::de::Error::custom(
                                                "invalid amount format",
                                            ));
                                        }
                                        builder = builder
                                            .with_amount(parts[0].parse().map_err(|_| {
                                                serde::de::Error::custom("invalid amount format")
                                            })?)
                                            .with_sending_amount_currency_code(Some(
                                                parts[1].to_string(),
                                            ))
                                            .with_uma_major_version(1);
                                    } else {
                                        return Err(serde::de::Error::custom(
                                            "invalid amount format",
                                        ));
                                    }
                                }
                                serde_json::Value::Number(n) => {
                                    let amount: i64 = n.as_i64().ok_or(
                                        serde::de::Error::custom("amount must be an integer"),
                                    )?;
                                    builder = builder.with_amount(amount);
                                }
                                _ => {
                                    return Err(serde::de::Error::custom("invalid amount format"));
                                }
                            }
                        }
                        "payerData" => {
                            let payer_data = map.next_value()?;
                            builder = builder.with_payer_data(payer_data);
                        }
                        "payeeData" => {
                            let requested_payee_data = map.next_value()?;
                            builder = builder.with_requested_payee_data(requested_payee_data);
                        }
                        "comment" => {
                            let comment = map.next_value()?;
                            builder = builder.with_comment(comment);
                        }
                        _ => {
                            let _: serde_json::Value = map.next_value()?;
                        }
                    }
                }
                Ok(builder.build())
            }
        }
        deserializer.deserialize_map(PayRequestVisitor)
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
    #[serde(rename = "convert")]
    receiving_currency_code: Option<String>,
    amount: String,
    payer_data: Option<PayerData>,
    #[serde(rename = "payeeData")]
    requested_payee_data: Option<CounterPartyDataOptions>,
    comment: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::protocol::pay_request::PayRequestV0;

    #[test]
    fn test_parse_v0_pay_request() {
        let json = r#"{"currency":"USD","amount":1000,"payerData":{"email":"email@themail.com","identifier":"$foo@bar.com","name":"Foo Bar"},"payeeData":null,"comment":"comment"}"#;
        let pay_request: super::PayRequest = serde_json::from_str(json).unwrap();
        assert_eq!(pay_request.receiving_currency_code, Some("USD".to_string()));
        assert_eq!(pay_request.amount, 1000);
        let payer_data = pay_request.payer_data.unwrap();
        assert_eq!(payer_data.identifier(), Some("$foo@bar.com"));
        assert_eq!(payer_data.email(), Some("email@themail.com"));
        assert_eq!(payer_data.name(), Some("Foo Bar"));
        assert_eq!(pay_request.requested_payee_data, None);
        assert_eq!(pay_request.comment, Some("comment".to_string()));
        assert_eq!(pay_request.uma_major_version, 0);
    }

    #[test]
    fn test_parse_v1_pay_request() {
        let json = r#"{"convert":"USD","amount":"1000.USD","payerData":{"email":"email@themail.com","identifier":"$foo@bar.com","name":"Foo Bar"},"payeeData":null,"comment":"comment"}"#;
        let pay_request: super::PayRequest = serde_json::from_str(json).unwrap();
        assert_eq!(pay_request.receiving_currency_code, Some("USD".to_string()));
        assert_eq!(
            pay_request.sending_amount_currency_code,
            Some("USD".to_string())
        );
        assert_eq!(pay_request.amount, 1000);
        let payer_data = pay_request.payer_data.unwrap();
        assert_eq!(payer_data.identifier(), Some("$foo@bar.com"));
        assert_eq!(payer_data.email(), Some("email@themail.com"));
        assert_eq!(payer_data.name(), Some("Foo Bar"));
        assert_eq!(pay_request.requested_payee_data, None);
        assert_eq!(pay_request.comment, Some("comment".to_string()));
        assert_eq!(pay_request.uma_major_version, 1);
    }

    #[test]
    fn test_serialize_v0_pay_request() {
        let pay_request = super::PayRequest {
            receiving_currency_code: Some("USD".to_string()),
            amount: 1000,
            payer_data: Some(super::PayerData(serde_json::json!({
                "email": "email@themail.com",
                "identifier": "$foo@bar.com",
                "name": "Foo Bar"
            }))),
            requested_payee_data: None,
            comment: Some("comment".to_string()),
            uma_major_version: 0,
            sending_amount_currency_code: None,
        };
        let json = serde_json::to_string(&pay_request).unwrap();
        let object: PayRequestV0 = serde_json::from_str(&json).unwrap();
        assert_eq!(object.receiving_currency_code, Some("USD".to_string()));
        assert_eq!(object.amount, 1000);
        let payer_data = object.payer_data.unwrap();
        assert_eq!(payer_data.identifier(), Some("$foo@bar.com"));
        assert_eq!(payer_data.email(), Some("email@themail.com"));
        assert_eq!(payer_data.name(), Some("Foo Bar"));
        assert_eq!(object.requested_payee_data, None);
        assert_eq!(object.comment, Some("comment".to_string()));
    }

    #[test]
    fn test_serialize_v1_pay_request() {
        let pay_request = super::PayRequest {
            receiving_currency_code: Some("USD".to_string()),
            amount: 1000,
            payer_data: Some(super::PayerData(serde_json::json!({
                "email": "email@themail.com",
                "identifier": "$foo@bar.com",
                "name": "Foo Bar"
            }))),
            requested_payee_data: None,
            comment: Some("comment".to_string()),
            uma_major_version: 1,
            sending_amount_currency_code: None,
        };
        let json = serde_json::to_string(&pay_request).unwrap();
        let object: super::PayRequestV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(object.receiving_currency_code, Some("USD".to_string()));
        assert_eq!(object.amount, "1000");
        let payer_data = object.payer_data.unwrap();
        assert_eq!(payer_data.identifier(), Some("$foo@bar.com"));
        assert_eq!(payer_data.email(), Some("email@themail.com"));
        assert_eq!(payer_data.name(), Some("Foo Bar"));
        assert_eq!(object.requested_payee_data, None);
        assert_eq!(object.comment, Some("comment".to_string()));
    }
}
