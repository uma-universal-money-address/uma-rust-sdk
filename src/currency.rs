use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Currency {
    // The ISO 4217 currency code of the currency (eg. USD).
    pub code: String,

    // The full display name of the currency (eg. US Dollars).
    pub name: String,

    // The symbol of the currency (eg. $ for USD).
    pub symbol: String,

    // The estimated millisatoshis per smallest "unit" of this currency (eg. 1 cent in USD).
    #[serde(rename = "multiplier")]
    pub millisatoshi_per_unit: i64,

    // The minimum amount of the currency that can be sent in a single transaction. This is in the
    // smallest unit of the currency (eg. cents for USD).
    #[serde(rename = "minSendable")]
    pub min_sendable: i64,

    // The maximum amount of the currency that can be sent in a single transaction. This is in the
    // smallest unit of the currency (eg. cents for USD).
    #[serde(rename = "maxSendable")]
    pub max_sendable: i64,

    // The number of digits after the decimal point for display on the sender side. For example,
    // in USD, by convention, there are 2 digits for cents - $5.95. in this case, `displayDecimals`
    // would be 2. Note that the multiplier is still always in the smallest unit (cents). This field
    // is only for display purposes. The sender should assume zero if this field is omitted, unless
    // they know the proper display format of the target currency.
    #[serde(rename = "displayDecimals")]
    pub display_decimals: Option<i64>,
}
