use std::fmt;

pub mod counter_party_data;
pub mod currency;
pub mod kyc_status;
pub mod lnurl_request;
pub mod lnurl_response;
pub mod pay_request;
pub mod payee_data;
pub mod payer_data;
pub mod payreq_response;
pub mod pub_key_response;
pub mod utxo_amount;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidReceiverAddress,
    InvalidUrl,
    MissingTimestamp,
    MissingNonce,
    MissingSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidReceiverAddress => write!(f, "Invalid receiver address"),
            Self::InvalidUrl => write!(f, "Invalid URL"),
            Self::MissingNonce => write!(f, "Missing nonce"),
            Self::MissingTimestamp => write!(f, "Missing timestamp"),
            Self::MissingSignature => write!(f, "Missing signature"),
        }
    }
}

impl std::error::Error for Error {}
