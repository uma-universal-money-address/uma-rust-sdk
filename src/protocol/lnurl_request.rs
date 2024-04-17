use serde::{Deserialize, Serialize};
use url::Url;

use super::Error;

/// LnurlpRequest is the first request in the UMA protocol.
/// It is sent by the VASP that is sending the payment to find out information about the receiver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LnurlpRequest {
    /// receiver_address is the address of the user at VASP2 that is receiving the payment.
    pub receiver_address: String,

    /// nonce is a random string that is used to prevent replay attacks.
    pub nonce: String,

    /// signature is the hex-encoded signature of sha256(receiver_address|nonce|timestamp).
    pub signature: String,

    /// is_subject_to_travel_rule indicates VASP1 is a financial institution that requires travel
    /// rule information.
    pub is_subject_to_travel_rule: bool,

    /// vasp_domain is the domain of the VASP that is sending the payment. It will be used by VASP2
    /// to fetch the public keys of VASP1.
    pub vasp_domain: String,

    /// timestamp is the unix timestamp of when the request was sent. Used in the signature.
    pub timestamp: i64,

    /// uma_version is the version of the UMA protocol that VASP1 prefers to use for this
    /// transaction. For the version negotiation flow,
    /// see https://static.swimlanes.io/87f5d188e080cb8e0494e46f80f2ae74.png
    pub uma_version: String,
}

impl LnurlpRequest {
    pub fn encode_to_url(&self) -> Result<url::Url, Error> {
        let receiver_address_parts: Vec<&str> = self.receiver_address.split('@').collect();
        if receiver_address_parts.len() != 2 {
            return Err(Error::InvalidReceiverAddress);
        }
        let scheme = if receiver_address_parts[1].starts_with("localhost:") {
            "http"
        } else {
            "https"
        };
        let mut lnurlp_url = Url::parse(&format!(
            "{}://{}/.well-known/lnurlp/{}",
            scheme, receiver_address_parts[1], receiver_address_parts[0]
        ))
        .map_err(|_| Error::InvalidUrl)?;

        lnurlp_url
            .query_pairs_mut()
            .append_pair("signature", &self.signature)
            .append_pair("vaspDomain", &self.vasp_domain)
            .append_pair("nonce", &self.nonce)
            .append_pair(
                "isSubjectToTravelRule",
                &self.is_subject_to_travel_rule.to_string(),
            )
            .append_pair("timestamp", &self.timestamp.to_string())
            .append_pair("umaVersion", &self.uma_version);

        Ok(lnurlp_url)
    }

    pub fn signable_payload(&self) -> Vec<u8> {
        let payload_string = format!(
            "{}|{}|{}",
            self.receiver_address, self.nonce, self.timestamp
        );
        payload_string.into_bytes()
    }
}
