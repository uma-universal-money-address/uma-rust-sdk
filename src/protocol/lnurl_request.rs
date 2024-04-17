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
    pub nonce: Option<String>,

    /// signature is the hex-encoded signature of sha256(receiver_address|nonce|timestamp).
    pub signature: Option<String>,

    /// is_subject_to_travel_rule indicates VASP1 is a financial institution that requires travel
    /// rule information.
    pub is_subject_to_travel_rule: Option<bool>,

    /// vasp_domain is the domain of the VASP that is sending the payment. It will be used by VASP2
    /// to fetch the public keys of VASP1.
    pub vasp_domain: Option<String>,

    /// timestamp is the unix timestamp of when the request was sent. Used in the signature.
    pub timestamp: Option<i64>,

    /// uma_version is the version of the UMA protocol that VASP1 prefers to use for this
    /// transaction. For the version negotiation flow,
    /// see https://static.swimlanes.io/87f5d188e080cb8e0494e46f80f2ae74.png
    pub uma_version: Option<String>,
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

        if let Some(signature) = &self.signature {
            lnurlp_url
                .query_pairs_mut()
                .append_pair("signature", signature);
        }

        if let Some(vasp_domain) = &self.vasp_domain {
            lnurlp_url
                .query_pairs_mut()
                .append_pair("vaspDomain", vasp_domain);
        }

        if let Some(nonce) = &self.nonce {
            lnurlp_url.query_pairs_mut().append_pair("nonce", nonce);
        }

        if let Some(is_subject_to_travel_rule) = self.is_subject_to_travel_rule {
            lnurlp_url.query_pairs_mut().append_pair(
                "isSubjectToTravelRule",
                &is_subject_to_travel_rule.to_string(),
            );
        }

        if let Some(timestamp) = &self.timestamp {
            lnurlp_url
                .query_pairs_mut()
                .append_pair("timestamp", &timestamp.to_string());
        }

        if let Some(uma_version) = &self.uma_version {
            lnurlp_url
                .query_pairs_mut()
                .append_pair("umaVersion", uma_version);
        }

        Ok(lnurlp_url)
    }

    pub fn signable_payload(&self) -> Result<Vec<u8>, Error> {
        let timestamp = self.timestamp.ok_or(Error::MissingTimestamp)?;
        let nonce = self.nonce.as_deref().ok_or(Error::MissingNonce)?;
        let payload_string = format!("{}|{}|{}", self.receiver_address, nonce, timestamp);
        Ok(payload_string.into_bytes())
    }
}
