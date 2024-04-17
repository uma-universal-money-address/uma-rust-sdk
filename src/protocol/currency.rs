use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Currency {
    // The ISO 4217 (if applicable) currency code (eg. "USD"). For cryptocurrencies, this will  be a ticker
    // symbol, such as BTC for Bitcoin.
    pub code: String,

    // The full display name of the currency (eg. US Dollars).
    pub name: String,

    // The symbol of the currency (eg. $ for USD).
    pub symbol: String,

    // The estimated millisatoshis per smallest "unit" of this currency (eg. 1 cent in USD).
    #[serde(rename = "multiplier")]
    pub millisatoshi_per_unit: f64,

    // The minimum amount of the currency that can be sent in a single transaction. This is in the
    // smallest unit of the currency (eg. cents for USD).
    #[serde(rename = "minSendable")]
    pub min_sendable: i64,

    // The maximum amount of the currency that can be sent in a single transaction. This is in the
    // smallest unit of the currency (eg. cents for USD).
    #[serde(rename = "maxSendable")]
    pub max_sendable: i64,

    // The number of digits after the decimal point for display on the sender side, and to add clarity
    // around what the "smallest unit" of the currency is. For example, in USD, by convention, there are 2 digits for
    // cents - $5.95. In this case, `decimals` would be 2. Note that the multiplier is still always in the smallest
    // unit (cents). In addition to display purposes, this field can be used to resolve ambiguity in what the multiplier
    // means. For example, if the currency is "BTC" and the multiplier is 1000, really we're exchanging in SATs, so
    // `decimals` would be 8.
    // For details on edge cases and examples, see https://github.com/uma-universal-money-address/protocol/blob/main/umad-04-lnurlp-response.md.
    pub decimals: i32,
}
