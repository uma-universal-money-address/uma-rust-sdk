use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
pub struct CounterPartyDataOption {
    pub mandatory: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CounterPartyDataField {
    #[serde(rename = "identifier")]
    CounterPartyDataFieldIdentifier,

    #[serde(rename = "name")]
    CounterPartyDataFieldName,

    #[serde(rename = "email")]
    CounterPartyDataFieldEmail,

    #[serde(rename = "countryCode")]
    CounterPartyDataFieldCountryCode,

    #[serde(rename = "compliance")]
    CounterPartyDataFieldCompliance,

    #[serde(rename = "accountNumber")]
    CounterPartyDataFieldAccountNumber,
}

impl ToString for CounterPartyDataField {
    fn to_string(&self) -> String {
        match self {
            CounterPartyDataField::CounterPartyDataFieldIdentifier => "identifier".to_string(),
            CounterPartyDataField::CounterPartyDataFieldName => "name".to_string(),
            CounterPartyDataField::CounterPartyDataFieldEmail => "email".to_string(),
            CounterPartyDataField::CounterPartyDataFieldCountryCode => "countryCode".to_string(),
            CounterPartyDataField::CounterPartyDataFieldCompliance => "compliance".to_string(),
            CounterPartyDataField::CounterPartyDataFieldAccountNumber => {
                "accountNumber".to_string()
            }
        }
    }
}

pub type CounterPartyDataOptions =
    std::collections::HashMap<CounterPartyDataField, CounterPartyDataOption>;
