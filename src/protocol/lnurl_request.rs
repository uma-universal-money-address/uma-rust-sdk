use serde::{Deserialize, Serialize};
use url::Url;
use url_builder::URLBuilder;

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
        let mut ub = URLBuilder::new();
        ub.set_protocol(scheme)
            .set_host(receiver_address_parts[1])
            .add_route(&format!(".well-known/lnurlp/{}", receiver_address_parts[0]));

        if let Some(signature) = &self.signature {
            ub.add_param("signature", signature);
        }

        if let Some(vasp_domain) = &self.vasp_domain {
            ub.add_param("vaspDomain", vasp_domain);
        }

        if let Some(nonce) = &self.nonce {
            ub.add_param("nonce", nonce);
        }

        if let Some(is_subject_to_travel_rule) = self.is_subject_to_travel_rule {
            ub.add_param(
                "isSubjectToTravelRule",
                &is_subject_to_travel_rule.to_string(),
            );
        }

        if let Some(timestamp) = &self.timestamp {
            ub.add_param("timestamp", &timestamp.to_string());
        }

        if let Some(uma_version) = &self.uma_version {
            ub.add_param("umaVersion", uma_version);
        }

        let url_string = ub.build();
        Url::parse(&url_string).map_err(|_| Error::InvalidUrl)
    }

    pub fn as_uma_lnurlp_request(&self) -> Option<UmaLnurlpRequest> {
        self.nonce.clone().and_then(|nonce| {
            self.signature.clone().and_then(|signature| {
                self.is_subject_to_travel_rule
                    .clone()
                    .and_then(|is_subject_to_travel_rule| {
                        self.vasp_domain.clone().and_then(|vasp_domain| {
                            self.timestamp.clone().and_then(|timestamp| {
                                self.uma_version
                                    .clone()
                                    .map(|uma_version| UmaLnurlpRequest {
                                        receiver_address: self.receiver_address.clone(),
                                        nonce,
                                        signature,
                                        is_subject_to_travel_rule,
                                        vasp_domain,
                                        timestamp,
                                        uma_version,
                                    })
                            })
                        })
                    })
            })
        })
    }

    pub fn signable_payload(&self) -> Result<Vec<u8>, Error> {
        let timestamp = self.timestamp.ok_or(Error::MissingTimestamp)?;
        let nonce = self.nonce.as_deref().ok_or(Error::MissingNonce)?;
        let payload_string = format!("{}|{}|{}", self.receiver_address, nonce, timestamp);
        Ok(payload_string.into_bytes())
    }
}

/// UmaLnurlpRequest is the first request in the UMA protocol.
/// It is sent by the VASP that is sending the payment to find out information about the receiver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UmaLnurlpRequest {
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

impl UmaLnurlpRequest {
    pub fn as_lnurl_request(&self) -> LnurlpRequest {
        LnurlpRequest {
            receiver_address: self.receiver_address.clone(),
            nonce: Some(self.nonce.clone()),
            signature: Some(self.signature.clone()),
            is_subject_to_travel_rule: Some(self.is_subject_to_travel_rule),
            vasp_domain: Some(self.vasp_domain.clone()),
            timestamp: Some(self.timestamp),
            uma_version: Some(self.uma_version.clone()),
        }
    }

    pub fn encode_to_url(&self) -> Result<url::Url, Error> {
        self.as_lnurl_request().encode_to_url()
    }

    pub fn signable_payload(&self) -> Vec<u8> {
        let payload_string = format!(
            "{}|{}|{}",
            self.receiver_address, self.nonce, self.timestamp
        );
        payload_string.into_bytes()
    }
}
