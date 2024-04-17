use std::fmt;

pub mod currency;
pub mod kyc_status;
pub mod lnurl_request;
pub mod lnurl_response;
pub mod pay_request;
pub mod payer_data;
pub mod payreq_response;
pub mod pub_key_response;
pub mod utxo_amount;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidReceiverAddress,
    InvalidUrl,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidReceiverAddress => write!(f, "Invalid receiver address"),
            Self::InvalidUrl => write!(f, "Invalid URL"),
        }
    }
}

impl std::error::Error for Error {}
