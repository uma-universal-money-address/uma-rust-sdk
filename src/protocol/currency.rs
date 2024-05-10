use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq)]
pub struct Currency {
    // The ISO 4217 (if applicable) currency code (eg. "USD"). For cryptocurrencies, this will  be a ticker
    // symbol, such as BTC for Bitcoin.
    pub code: String,

    // The full display name of the currency (eg. US Dollars).
    pub name: String,

    // The symbol of the currency (eg. $ for USD).
    pub symbol: String,

    // The estimated millisatoshis per smallest "unit" of this currency (eg. 1 cent in USD).
    pub millisatoshi_per_unit: f64,

    // Convertible is a struct which contains the range of amounts that can be sent in a single transaction.
    pub convertible_currency: ConvertibleCurrency,

    // The number of digits after the decimal point for display on the sender side, and to add clarity
    // around what the "smallest unit" of the currency is. For example, in USD, by convention, there are 2 digits for
    // cents - $5.95. In this case, `decimals` would be 2. Note that the multiplier is still always in the smallest
    // unit (cents). In addition to display purposes, this field can be used to resolve ambiguity in what the multiplier
    // means. For example, if the currency is "BTC" and the multiplier is 1000, really we're exchanging in SATs, so
    // `decimals` would be 8.
    // For details on edge cases and examples, see https://github.com/uma-universal-money-address/protocol/blob/main/umad-04-lnurlp-response.md.
    pub decimals: i32,

    // UmaMajorVersion is the major version of the UMA protocol that the VASP supports for this currency. This is used
    // for serialization, but is not serialized itself.
    pub uma_major_version: i32,
}

pub struct CurrencyBuilder {
    code: Option<String>,
    name: Option<String>,
    symbol: Option<String>,
    millisatoshi_per_unit: Option<f64>,
    convertible_currency_builder: Option<ConvertibleCurrencyBuilder>,
    decimals: Option<i32>,
    uma_major_version: Option<i32>,
}

impl Default for CurrencyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CurrencyBuilder {
    pub fn new() -> CurrencyBuilder {
        CurrencyBuilder {
            code: None,
            name: None,
            symbol: None,
            millisatoshi_per_unit: None,
            convertible_currency_builder: None,
            decimals: None,
            uma_major_version: None,
        }
    }

    pub fn code(mut self, code: String) -> CurrencyBuilder {
        self.code = Some(code);
        self
    }

    pub fn name(mut self, name: String) -> CurrencyBuilder {
        self.name = Some(name);
        self
    }

    pub fn symbol(mut self, symbol: String) -> CurrencyBuilder {
        self.symbol = Some(symbol);
        self
    }

    pub fn millisatoshi_per_unit(mut self, millisatoshi_per_unit: f64) -> CurrencyBuilder {
        self.millisatoshi_per_unit = Some(millisatoshi_per_unit);
        self
    }

    pub fn convertible_currency(
        mut self,
        convertible_currency: ConvertibleCurrency,
    ) -> CurrencyBuilder {
        let builder = ConvertibleCurrencyBuilder::new()
            .min_sendable(convertible_currency.min_sendable)
            .max_sendable(convertible_currency.max_sendable);
        self.convertible_currency_builder = Some(builder);
        self
    }

    pub fn decimals(mut self, decimals: i32) -> CurrencyBuilder {
        self.decimals = Some(decimals);
        self
    }

    pub fn uma_major_version(mut self, uma_major_version: i32) -> CurrencyBuilder {
        self.uma_major_version = Some(uma_major_version);
        self
    }

    pub fn min_sendable(mut self, min_sendable: i64) -> CurrencyBuilder {
        self.convertible_currency_builder = Some(
            self.convertible_currency_builder
                .unwrap_or_default()
                .min_sendable(min_sendable),
        );
        self
    }

    pub fn max_sendable(mut self, max_sendable: i64) -> CurrencyBuilder {
        self.convertible_currency_builder = Some(
            self.convertible_currency_builder
                .unwrap_or_default()
                .max_sendable(max_sendable),
        );
        self
    }

    pub fn build(self) -> Option<Currency> {
        Some(Currency {
            code: self.code?,
            name: self.name?,
            symbol: self.symbol?,
            millisatoshi_per_unit: self.millisatoshi_per_unit?,
            convertible_currency: self.convertible_currency_builder?.build()?,
            decimals: self.decimals?,
            uma_major_version: self.uma_major_version?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConvertibleCurrency {
    // MinSendable is the minimum amount of the currency that can be sent in a single transaction. This is in the
    // smallest unit of the currency (eg. cents for USD).
    #[serde(rename = "min")]
    pub min_sendable: i64,

    // MaxSendable is the maximum amount of the currency that can be sent in a single transaction. This is in the
    // smallest unit of the currency (eg. cents for USD).
    #[serde(rename = "max")]
    pub max_sendable: i64,
}

pub struct ConvertibleCurrencyBuilder {
    min_sendable: Option<i64>,
    max_sendable: Option<i64>,
}

impl Default for ConvertibleCurrencyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConvertibleCurrencyBuilder {
    pub fn new() -> ConvertibleCurrencyBuilder {
        ConvertibleCurrencyBuilder {
            min_sendable: None,
            max_sendable: None,
        }
    }

    pub fn min_sendable(mut self, min_sendable: i64) -> ConvertibleCurrencyBuilder {
        self.min_sendable = Some(min_sendable);
        self
    }

    pub fn max_sendable(mut self, max_sendable: i64) -> ConvertibleCurrencyBuilder {
        self.max_sendable = Some(max_sendable);
        self
    }

    pub fn build(self) -> Option<ConvertibleCurrency> {
        Some(ConvertibleCurrency {
            min_sendable: self.min_sendable?,
            max_sendable: self.max_sendable?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct CurrencyV0 {
    pub code: String,
    pub name: String,
    pub symbol: String,
    #[serde(rename = "multiplier")]
    pub millisatoshi_per_unit: f64,
    pub min_sendable: i64,
    pub max_sendable: i64,
    pub decimals: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct CurrencyV1 {
    pub code: String,
    pub name: String,
    pub symbol: String,
    #[serde(rename = "multiplier")]
    pub millisatoshi_per_unit: f64,
    #[serde(rename = "convertible")]
    pub convertible_currency: ConvertibleCurrency,
    pub decimals: i32,
}

impl Serialize for Currency {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.uma_major_version == 0 {
            let currency = CurrencyV0 {
                code: self.code.clone(),
                name: self.name.clone(),
                symbol: self.symbol.clone(),
                millisatoshi_per_unit: self.millisatoshi_per_unit,
                min_sendable: self.convertible_currency.min_sendable,
                max_sendable: self.convertible_currency.max_sendable,
                decimals: self.decimals,
            };
            currency.serialize(serializer)
        } else {
            let currency = CurrencyV1 {
                code: self.code.clone(),
                name: self.name.clone(),
                symbol: self.symbol.clone(),
                millisatoshi_per_unit: self.millisatoshi_per_unit,
                convertible_currency: self.convertible_currency.clone(),
                decimals: self.decimals,
            };
            currency.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Currency {
    fn deserialize<D>(deserializer: D) -> Result<Currency, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};

        struct CurrencyVisitor;

        impl<'de> Visitor<'de> for CurrencyVisitor {
            type Value = Currency;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "Currency json value")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Currency, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut builder = CurrencyBuilder::new();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "code" => {
                            let code: String = map.next_value()?;
                            builder = builder.code(code);
                        }
                        "name" => {
                            let name: String = map.next_value()?;
                            builder = builder.name(name);
                        }
                        "symbol" => {
                            let symbol: String = map.next_value()?;
                            builder = builder.symbol(symbol);
                        }
                        "multiplier" => {
                            let millisatoshi_per_unit: f64 = map.next_value()?;
                            builder = builder.millisatoshi_per_unit(millisatoshi_per_unit);
                        }
                        "minSendable" => {
                            let min_sendable: i64 = map.next_value()?;
                            builder = builder.min_sendable(min_sendable).uma_major_version(0);
                        }
                        "maxSendable" => {
                            let max_sendable: i64 = map.next_value()?;
                            builder = builder.max_sendable(max_sendable).uma_major_version(0);
                        }
                        "convertible" => {
                            let convertible_currency: ConvertibleCurrency = map.next_value()?;
                            builder = builder
                                .convertible_currency(convertible_currency)
                                .uma_major_version(1);
                        }
                        "decimals" => {
                            let decimals: i32 = map.next_value()?;
                            builder = builder.decimals(decimals);
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
        deserializer.deserialize_map(CurrencyVisitor)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_parse_v0_currency() {
        let json = r#"{"code":"USD","name":"US Dollars","symbol":"$","multiplier":1000.0,"minSendable":1000,"maxSendable":1000000,"decimals":2}"#;
        let currency: super::Currency = serde_json::from_str(json).unwrap();
        assert_eq!(currency.code, "USD");
        assert_eq!(currency.name, "US Dollars");
        assert_eq!(currency.symbol, "$");
        assert_eq!(currency.millisatoshi_per_unit, 1000.0);
        assert_eq!(currency.convertible_currency.min_sendable, 1000);
        assert_eq!(currency.convertible_currency.max_sendable, 1000000);
        assert_eq!(currency.decimals, 2);
        assert_eq!(currency.uma_major_version, 0);
    }

    #[test]
    fn test_parse_v1_currency() {
        let json = r#"{"code":"BTC","name":"Bitcoin","symbol":"₿","multiplier":1000.0,"convertible":{"min":1000,"max":1000000},"decimals":8}"#;
        let currency: super::Currency = serde_json::from_str(json).unwrap();
        assert_eq!(currency.code, "BTC");
        assert_eq!(currency.name, "Bitcoin");
        assert_eq!(currency.symbol, "₿");
        assert_eq!(currency.millisatoshi_per_unit, 1000.0);
        assert_eq!(currency.convertible_currency.min_sendable, 1000);
        assert_eq!(currency.convertible_currency.max_sendable, 1000000);
        assert_eq!(currency.decimals, 8);
        assert_eq!(currency.uma_major_version, 1);
    }

    #[test]
    fn test_serialize_v0_currency() {
        let currency = super::Currency {
            code: "USD".to_string(),
            name: "US Dollars".to_string(),
            symbol: "$".to_string(),
            millisatoshi_per_unit: 1000.0,
            convertible_currency: super::ConvertibleCurrency {
                min_sendable: 1000,
                max_sendable: 1000000,
            },
            decimals: 2,
            uma_major_version: 0,
        };
        let serialized = serde_json::to_string(&currency).unwrap();
        let expected = r#"{"code":"USD","name":"US Dollars","symbol":"$","multiplier":1000.0,"minSendable":1000,"maxSendable":1000000,"decimals":2}"#;
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_v1_currency() {
        let currency = super::Currency {
            code: "BTC".to_string(),
            name: "Bitcoin".to_string(),
            symbol: "₿".to_string(),
            millisatoshi_per_unit: 1000.0,
            convertible_currency: super::ConvertibleCurrency {
                min_sendable: 1000,
                max_sendable: 1000000,
            },
            decimals: 8,
            uma_major_version: 1,
        };
        let serialized = serde_json::to_string(&currency).unwrap();
        let expected = r#"{"code":"BTC","name":"Bitcoin","symbol":"₿","multiplier":1000.0,"convertible":{"min":1000,"max":1000000},"decimals":8}"#;
        assert_eq!(serialized, expected);
    }
}
