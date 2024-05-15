use serde::{Deserialize, Serialize};
use x509_cert::{
    der::{Decode as _, Encode as _},
    Certificate,
};

use super::Error;

/// PubKeyResponse is sent from a VASP to another VASP to provide its public keys.
/// It is the response to GET requests at `/.well-known/lnurlpubkey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubKeyResponse {
    // signing_cert_chain is the DER-encoded certificate chain used to verify signatures from a VASP.
    pub signing_cert_chain: Option<Vec<Certificate>>,

    // EncryptionCertChain is the DER-encoded certificate chain used to encrypt TR info sent to a VASP.
    pub encryption_cert_chain: Option<Vec<Certificate>>,

    /// signing_pub_key is used to verify signatures from a VASP.
    pub signing_pub_key: Option<String>,

    // encryption_pub_key is used to encrypt TR info sent to a VASP.
    pub encryption_pub_key: Option<String>,

    // expiration_timestamp [Optional] Seconds since epoch at which these pub keys must be refreshed.
    // They can be safely cached until this expiration (or forever if null).
    pub expiration_timestamp: Option<i64>,
}

impl PubKeyResponse {
    fn get_pubkey(
        &self,
        certs: Option<Vec<Certificate>>,
        pubkey: Option<String>,
    ) -> Result<Option<Vec<u8>>, Error> {
        if let Some(certs) = certs {
            if let Some(cert) = certs.first() {
                if let Some(pubkey) = cert
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .as_bytes()
                {
                    return Ok(Some(pubkey.to_vec()));
                }
            }
        }
        if let Some(pubkey) = pubkey {
            return Ok(Some(hex::decode(pubkey).map_err(|_| Error::InvalidPubkey)?));
        }
        Ok(None)
    }

    pub fn signing_pubkey(&self) -> Result<Option<Vec<u8>>, Error> {
        self.get_pubkey(
            self.signing_cert_chain.clone(),
            self.signing_pub_key.clone(),
        )
    }

    pub fn encryption_pubkey(&self) -> Result<Option<Vec<u8>>, Error> {
        self.get_pubkey(
            self.encryption_cert_chain.clone(),
            self.encryption_pub_key.clone(),
        )
    }
}

impl Serialize for PubKeyResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let signing_cert_chain = self.signing_cert_chain.as_ref().map(|certs| {
            certs
                .iter()
                .map(|cert| hex::encode(cert.to_der().expect("failed to encode certificate")))
                .collect()
        });
        let encryption_cert_chain = self.encryption_cert_chain.as_ref().map(|certs| {
            certs
                .iter()
                .map(|cert| hex::encode(cert.to_der().expect("failed to encode certificate")))
                .collect()
        });
        let json = PubKeyResponseJson {
            signing_cert_chain,
            encryption_cert_chain,
            signing_pub_key: self.signing_pub_key.clone(),
            encryption_pub_key: self.encryption_pub_key.clone(),
            expiration_timestamp: self.expiration_timestamp,
        };
        json.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PubKeyResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let json = PubKeyResponseJson::deserialize(deserializer)?;
        let signing_cert_chain = json.signing_cert_chain.map(|certs| {
            certs
                .into_iter()
                .map(|cert| {
                    Certificate::from_der(&hex::decode(cert).expect("failed to decode certificate"))
                        .expect("failed to parse certificate")
                })
                .collect()
        });
        let encryption_cert_chain = json.encryption_cert_chain.map(|certs| {
            certs
                .into_iter()
                .map(|cert| {
                    Certificate::from_der(&hex::decode(cert).expect("failed to decode certificate"))
                        .expect("failed to parse certificate")
                })
                .collect()
        });
        Ok(Self {
            signing_cert_chain,
            encryption_cert_chain,
            signing_pub_key: json.signing_pub_key,
            encryption_pub_key: json.encryption_pub_key,
            expiration_timestamp: json.expiration_timestamp,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PubKeyResponseJson {
    signing_cert_chain: Option<Vec<String>>,
    encryption_cert_chain: Option<Vec<String>>,
    signing_pub_key: Option<String>,
    encryption_pub_key: Option<String>,
    expiration_timestamp: Option<i64>,
}
