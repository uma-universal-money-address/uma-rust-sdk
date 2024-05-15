use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::payee_data::{CompliancePayeeData, PayeeData};

/// PayReqResponse is the response sent by the receiver to the sender to provide an invoice.
#[derive(Debug, Clone, PartialEq)]
pub struct PayReqResponse {
    /// encoded_invoice is the BOLT11 invoice that the sender will pay.
    pub encoded_invoice: String,
    /// routes is usually just an empty list from legacy LNURL, which was replaced by route hints in
    /// the BOLT11 invoice.
    pub routes: Vec<Route>,
    // PaymentInfo is information about the payment that the receiver will receive. Includes Final currency-related
    // information for the payment. Required for UMA.
    pub payment_info: Option<PayReqResponsePaymentInfo>,
    // PayeeData The data about the receiver that the sending VASP requested in the payreq request.
    // Required for UMA.
    pub payee_data: Option<PayeeData>,
    // Disposable This field may be used by a WALLET to decide whether the initial LNURL link will  be stored locally
    // for later reuse or erased. If disposable is null, it should be interpreted as true, so if SERVICE intends its
    // LNURL links to be stored it must return `disposable: false`. UMA should never return `disposable: false` due to
    // signature nonce checks, etc. See LUD-11.
    pub disposable: Option<bool>,
    // SuccessAction defines a struct which can be stored and shown to the user on payment success. See LUD-09.
    pub success_action: Option<HashMap<String, String>>,
    // UmaMajorVersion is the major version of the UMA protocol that the receiver is using. Only used
    // for serialization and deserialization. Not included in the JSON response.
    pub uma_major_version: i32,
}

pub struct PayReqResponseBuilder {
    encoded_invoice: Option<String>,
    routes: Option<Vec<Route>>,
    payment_info: Option<PayReqResponsePaymentInfo>,
    payee_data: Option<PayeeData>,
    disposable: Option<bool>,
    success_action: Option<HashMap<String, String>>,
    uma_major_version: Option<i32>,
}

impl Default for PayReqResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PayReqResponseBuilder {
    pub fn new() -> Self {
        Self {
            encoded_invoice: None,
            routes: None,
            payment_info: None,
            payee_data: None,
            disposable: None,
            success_action: None,
            uma_major_version: None,
        }
    }

    pub fn encoded_invoice(mut self, encoded_invoice: String) -> Self {
        self.encoded_invoice = Some(encoded_invoice);
        self
    }

    pub fn routes(mut self, routes: Vec<Route>) -> Self {
        self.routes = Some(routes);
        self
    }

    pub fn payment_info(mut self, payment_info: PayReqResponsePaymentInfo) -> Self {
        self.payment_info = Some(payment_info);
        self
    }

    pub fn payee_data(mut self, payee_data: PayeeData) -> Self {
        self.payee_data = Some(payee_data);
        self
    }

    pub fn disposable(mut self, disposable: bool) -> Self {
        self.disposable = Some(disposable);
        self
    }

    pub fn success_action(mut self, success_action: HashMap<String, String>) -> Self {
        self.success_action = Some(success_action);
        self
    }

    pub fn uma_major_version(mut self, uma_major_version: i32) -> Self {
        self.uma_major_version = Some(uma_major_version);
        self
    }

    pub fn build(self) -> Option<PayReqResponse> {
        Some(PayReqResponse {
            encoded_invoice: self.encoded_invoice?,
            routes: self.routes?,
            payment_info: self.payment_info,
            payee_data: self.payee_data,
            disposable: self.disposable,
            success_action: self.success_action,
            uma_major_version: self.uma_major_version?,
        })
    }
}

impl PayReqResponse {
    pub fn is_uma_response(&self) -> bool {
        if self.payment_info.is_none() {
            return true;
        }

        if let Some(payee_data) = &self.payee_data {
            if let Ok(compliance) = payee_data.compliance() {
                return compliance.is_some();
            }
        }

        false
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub pubkey: String,
    pub path: Vec<Path>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Path {
    pub pubkey: String,
    pub fee: i64,
    pub msatoshi: i64,
    pub channel: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PayReqResponseCompliance {
    /// node_pub_key is the public key of the receiver's node if known.
    #[serde(rename = "nodePubKey")]
    pub node_pub_key: Option<String>,

    /// utxos is a list of UTXOs of channels over which the receiver will likely receive the
    /// payment.
    pub utxos: Vec<String>,

    /// utxo_callback is the URL that the sender VASP will call to send UTXOs of the channel that
    /// the sender used to send the payment once it completes.
    #[serde(rename = "utxoCallback")]
    pub utxo_callback: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PayReqResponsePaymentInfo {
    // Amount is the amount that the receiver will receive in the receiving currency not including fees. The amount is
    //    specified in the smallest unit of the currency (eg. cents for USD).
    pub amount: Option<i64>,

    /// CurrencyCode is the ISO 3-digit currency code that the receiver will receive for this
    /// payment.
    #[serde(rename = "currencyCode")]
    pub currency_code: String,

    /// Number of digits after the decimal point for the receiving currency. For example, in USD, by
    /// convention, there are 2 digits for cents - $5.95. In this case, `decimals` would be 2. This should align with
    /// the currency's `decimals` field in the LNURLP response. It is included here for convenience. See
    /// [UMAD-04](https://github.com/uma-universal-money-address/protocol/blob/main/umad-04-lnurlp-response.md) for
    /// details, edge cases, and examples.
    pub decimals: i32,

    /// Multiplier is the conversion rate. It is the number of millisatoshis that the receiver will
    /// receive for 1 unit of the specified currency.
    pub multiplier: f64,

    /// ExchangeFeesMillisatoshi is the fees charged (in millisats) by the receiving VASP for this
    /// transaction. This is separate from the Multiplier.
    #[serde(rename = "fee")]
    pub exchange_fees_millisatoshi: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct PayReqResponsePaymentInfoV0 {
    currency_code: String,
    multiplier: f64,
    decimals: i32,
    exchange_fees_millisatoshi: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct PayReqResponseV0 {
    #[serde(rename = "pr")]
    encoded_invoice: String,
    routes: Vec<Route>,
    payment_info: Option<PayReqResponsePaymentInfoV0>,
    payee_data: Option<PayeeData>,
    disposable: Option<bool>,
    success_action: Option<HashMap<String, String>>,
    compliance: Option<CompliancePayeeData>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct PayReqResponseV1 {
    #[serde(rename = "pr")]
    encoded_invoice: String,
    routes: Vec<Route>,
    #[serde(rename = "converted")]
    payment_info: Option<PayReqResponsePaymentInfo>,
    payee_data: Option<PayeeData>,
    disposable: Option<bool>,
    success_action: Option<HashMap<String, String>>,
}

impl Serialize for PayReqResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.uma_major_version == 0 {
            let payment_info = self.payment_info.as_ref().map(|payment_info| PayReqResponsePaymentInfoV0 {
                    currency_code: payment_info.currency_code.clone(),
                    multiplier: payment_info.multiplier,
                    decimals: payment_info.decimals,
                    exchange_fees_millisatoshi: payment_info.exchange_fees_millisatoshi,
                });
            let compliance = match &self.payee_data {
                Some(payee_data) => match payee_data.compliance() {
                    Ok(Some(compliance)) => Some(compliance),
                    _ => return Err(serde::ser::Error::custom("missing compliance")),
                },
                None => None,
            };
            let v0 = PayReqResponseV0 {
                encoded_invoice: self.encoded_invoice.clone(),
                routes: self.routes.clone(),
                payment_info,
                payee_data: self.payee_data.clone(),
                disposable: self.disposable,
                success_action: self.success_action.clone(),
                compliance,
            };
            v0.serialize(serializer)
        } else {
            let v1 = PayReqResponseV1 {
                encoded_invoice: self.encoded_invoice.clone(),
                routes: self.routes.clone(),
                payment_info: self.payment_info.clone(),
                payee_data: self.payee_data.clone(),
                disposable: self.disposable,
                success_action: self.success_action.clone(),
            };
            v1.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for PayReqResponse {
    fn deserialize<D>(deserializer: D) -> Result<PayReqResponse, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};

        struct PayReqResponseVisitor;

        impl<'de> Visitor<'de> for PayReqResponseVisitor {
            type Value = PayReqResponse;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a PayReqResponse")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut builder = PayReqResponseBuilder::new();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "pr" => {
                            let encoded_invoice = map.next_value::<String>()?;
                            builder = builder.encoded_invoice(encoded_invoice);
                        }
                        "routes" => {
                            let routes = map.next_value::<Vec<Route>>()?;
                            builder = builder.routes(routes);
                        }
                        "converted" => {
                            let payment_info = map.next_value::<PayReqResponsePaymentInfo>()?;
                            builder = builder.payment_info(payment_info).uma_major_version(1);
                        }
                        "payment_info" => {
                            let payment_info = map.next_value::<PayReqResponsePaymentInfoV0>()?;
                            builder = builder
                                .payment_info(PayReqResponsePaymentInfo {
                                    amount: None,
                                    currency_code: payment_info.currency_code,
                                    decimals: payment_info.decimals,
                                    multiplier: payment_info.multiplier,
                                    exchange_fees_millisatoshi: payment_info
                                        .exchange_fees_millisatoshi,
                                })
                                .uma_major_version(0);
                        }
                        "payeeData" => {
                            let payee_data = map.next_value::<PayeeData>()?;
                            builder = builder.payee_data(payee_data);
                        }
                        "disposable" => {
                            let disposable = map.next_value::<bool>()?;
                            builder = builder.disposable(disposable);
                        }
                        "successAction" => {
                            let success_action = map.next_value::<HashMap<String, String>>()?;
                            builder = builder.success_action(success_action);
                        }
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                builder
                    .build()
                    .ok_or_else(|| serde::de::Error::custom("missing field"))
            }
        }

        deserializer.deserialize_map(PayReqResponseVisitor)
    }
}
