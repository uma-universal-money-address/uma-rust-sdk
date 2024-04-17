use serde::{Deserialize, Serialize};

/// PayReqResponse is the response sent by the receiver to the sender to provide an invoice.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PayReqResponse {
    /// encoded_invoice is the BOLT11 invoice that the sender will pay.
    #[serde(rename = "pr")]
    pub encoded_invoice: String,

    /// routes is usually just an empty list from legacy LNURL, which was replaced by route hints in
    /// the BOLT11 invoice.
    pub routes: Vec<Route>,

    pub compliance: PayReqResponseCompliance,

    #[serde(rename = "paymentInfo")]
    pub payment_info: PayReqResponsePaymentInfo,
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
    #[serde(rename = "multiplier")]
    pub multiplier: f64,

    /// ExchangeFeesMillisatoshi is the fees charged (in millisats) by the receiving VASP for this
    /// transaction. This is separate from the Multiplier.
    #[serde(rename = "exchangeFeesMillisatoshi")]
    pub exchange_fees_millisatoshi: i64,
}
