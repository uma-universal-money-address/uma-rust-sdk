use serde::{Deserialize, Serialize};

use super::Error;

/// PubKeyResponse is sent from a VASP to another VASP to provide its public keys.
/// It is the response to GET requests at `/.well-known/lnurlpubkey`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PubKeyResponse {
    // signing_cert_chain is the DER-encoded certificate chain used to verify signatures from a VASP.
    pub signing_cert_chain: Option<Vec<String>>,

    // EncryptionCertChain is the DER-encoded certificate chain used to encrypt TR info sent to a VASP.
    pub encryption_cert_chain: Option<Vec<String>>,

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
        certs: Option<Vec<String>>,
        pubkey: Option<String>,
    ) -> Result<Option<Vec<u8>>, Error> {
        if let Some(certs) = certs {
            if let Some(cert) = certs.first() {
                let data = hex::decode(cert).map_err(|_| Error::InvalidPubkeyCert)?;
                let x509 = x509_parser::parse_x509_certificate(data.as_ref())
                    .map_err(|_| Error::InvalidPubkeyCert)?;
                match x509
                    .1
                    .public_key()
                    .parsed()
                    .map_err(|_| Error::InvalidPubkeyCert)?
                {
                    x509_parser::public_key::PublicKey::EC(ec) => {
                        return Ok(Some(ec.data().to_vec()));
                    }
                    _ => {
                        return Err(Error::InvalidPubkeyCert);
                    }
                };
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
