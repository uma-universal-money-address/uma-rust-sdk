use bitcoin::secp256k1::{
    ecdsa::Signature, hashes::sha256, Message, PublicKey, Secp256k1, SecretKey,
};
use rand_core::{OsRng, RngCore};
use std::{collections::HashMap, fmt};
use x509_cert::{der::Decode, Certificate};

use crate::{
    nonce_cache::NonceCache,
    protocol::{
        counter_party_data::{CounterPartyDataField, CounterPartyDataOptions},
        currency::Currency,
        kyc_status::KycStatus,
        lnurl_request::{LnurlpRequest, UmaLnurlpRequest},
        lnurl_response::{LnurlComplianceResponse, LnurlpResponse},
        pay_request::PayRequest,
        payee_data::{CompliancePayeeData, CompliancePayeeDataBuilder, PayeeData},
        payer_data::{CompliancePayerData, PayerData, TravelRuleFormat},
        payreq_response::{PayReqResponse, PayReqResponsePaymentInfo},
        post_transaction_callback::{
            PostTransactionCallback, PostTransactionCallbackBuilder, UtxoWithAmount,
        },
        pub_key_response::PubKeyResponse,
    },
    version::UnsupportedVersionError,
};

use crate::{
    public_key_cache,
    version::{self, is_version_supported},
};

#[derive(Debug)]
pub enum Error {
    Secp256k1Error(bitcoin::secp256k1::Error),
    EciesSecp256k1Error(ecies::SecpError),
    SignatureFormatError,
    InvalidSignature,
    InvalidResponse,
    ProtocolError(crate::protocol::Error),
    MissingUrlParam(String),
    InvalidUrlPath,
    InvalidHost,
    InvalidData(serde_json::Error),
    CreateInvoiceError(String),
    InvalidUMAAddress,
    InvalidVersion,
    UnsupportedVersion(UnsupportedVersionError),
    InvalidCertificatePemFormat,
    InvalidCurrencyFields,
    MissingUmaField(String),
    UnsupportedCurrency,
    InvalidPayeeData,
    InvalidPayerData,
    NonceError,
    UnsupportedUmaVersion(i32, i32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Secp256k1Error(err) => write!(f, "Secp256k1 error {}", err),
            Self::EciesSecp256k1Error(err) => write!(f, "Ecies Secp256k1 error {}", err),
            Self::SignatureFormatError => write!(f, "Signature format error"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::InvalidResponse => write!(f, "Invalid response"),
            Self::ProtocolError(err) => write!(f, "Protocol error {}", err),
            Self::MissingUrlParam(param) => write!(f, "Missing URL param {}", param),
            Self::InvalidUrlPath => write!(f, "Invalid URL path"),
            Self::InvalidHost => write!(f, "Invalid host"),
            Self::InvalidData(err) => write!(f, "Invalid data {}", err),
            Self::CreateInvoiceError(err) => write!(f, "Create invoice error {}", err),
            Self::InvalidUMAAddress => write!(f, "Invalid UMA address"),
            Self::InvalidVersion => write!(f, "Invalid version"),
            Self::UnsupportedVersion(version) => write!(
                f,
                "Unsupported version {:?}, supported version: {:?}",
                version.unsupported_version, version.supported_major_versions
            ),
            Self::InvalidCertificatePemFormat => write!(f, "Invalid certificate PEM format"),
            Self::InvalidCurrencyFields => {
                write!(f, "Invalid currency fields, must be all nil or all non-nil")
            }
            Self::MissingUmaField(field) => write!(f, "Missing UMA field {}", field),
            Self::UnsupportedCurrency => write!(
                f,
                "the sdk only supports sending in either SAT or the receiving currency"
            ),
            Self::InvalidPayeeData => write!(f, "Invalid payee data"),
            Self::InvalidPayerData => write!(f, "Invalid payer data"),
            Self::NonceError => write!(f, "Nonce error"),
            Self::UnsupportedUmaVersion(version, supported_version) => {
                write!(
                    f,
                    "Unsupported UMA version {}, version {} is required",
                    version, supported_version
                )
            }
        }
    }
}

/// Fetches the public key for another VASP.
///
/// If the public key is not in the cache, it will be fetched from the VASP's domain.
///     The public key will be cached for future use.
///
/// # Arguments
///
/// * `vasp_domain` - the domain of the VASP.
/// * `cache` - the PublicKeyCache cache to use. You can use the InMemoryPublicKeyCache struct, or implement your own persistent cache with any storage type.
pub fn fetch_public_key_for_vasp<T>(
    vasp_domain: &str,
    public_key_cache: &mut T,
) -> Result<PubKeyResponse, Error>
where
    T: public_key_cache::PublicKeyCache,
{
    let publick_key = public_key_cache.fetch_public_key_for_vasp(vasp_domain);
    if let Some(public_key) = publick_key {
        return Ok(public_key.clone());
    }

    let scheme = match vasp_domain.starts_with("localhost:") {
        true => "http",
        false => "https",
    };

    let url = format!("{}//{}/.well-known/lnurlpubkey", scheme, vasp_domain);
    let response = reqwest::blocking::get(url).map_err(|_| Error::InvalidResponse)?;

    if !response.status().is_success() {
        return Err(Error::InvalidResponse);
    }

    let bytes = response.bytes().map_err(|_| Error::InvalidResponse)?;

    let pubkey_response: PubKeyResponse =
        serde_json::from_slice(&bytes).map_err(Error::InvalidData)?;

    public_key_cache.add_public_key_for_vasp(vasp_domain, &pubkey_response);
    Ok(pubkey_response)
}

pub fn get_pubkey_response(
    signing_cert_chain_pem: &str,
    encryption_cert_chain_pem: &str,
    expiration_timestamp: Option<i64>,
) -> Result<PubKeyResponse, Error> {
    let signing_certs = pem::parse_many(signing_cert_chain_pem)
        .map_err(|_| Error::InvalidCertificatePemFormat)?
        .iter()
        .map(|pem| {
            Certificate::from_der(pem.contents()).map_err(|_| Error::InvalidCertificatePemFormat)
        })
        .collect::<Result<Vec<Certificate>, Error>>()?;
    let encryption_certs = pem::parse_many(encryption_cert_chain_pem)
        .map_err(|_| Error::InvalidCertificatePemFormat)?
        .iter()
        .map(|pem| {
            Certificate::from_der(pem.contents()).map_err(|_| Error::InvalidCertificatePemFormat)
        })
        .collect::<Result<Vec<Certificate>, Error>>()?;
    let signing_pubkey = signing_certs
        .first()
        .and_then(|cert| {
            cert.tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
        })
        .map(hex::encode)
        .ok_or(Error::InvalidCertificatePemFormat)?;
    let encryption_pubkey = encryption_certs
        .first()
        .and_then(|cert| {
            cert.tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
        })
        .map(hex::encode)
        .ok_or(Error::InvalidCertificatePemFormat)?;
    Ok(PubKeyResponse {
        signing_cert_chain: Some(signing_certs),
        encryption_cert_chain: Some(encryption_certs),
        signing_pub_key: Some(signing_pubkey),
        encryption_pub_key: Some(encryption_pubkey),
        expiration_timestamp,
    })
}

pub fn generate_nonce() -> String {
    OsRng.next_u64().to_string()
}

fn sign_payload(payload: &[u8], private_key_bytes: &[u8]) -> Result<String, Error> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(private_key_bytes).map_err(Error::Secp256k1Error)?;
    let msg = Message::from_hashed_data::<sha256::Hash>(payload);
    let signature = secp.sign_ecdsa(&msg, &sk);
    let sig_string = hex::encode(signature.serialize_der());
    Ok(sig_string)
}

fn verify_ecdsa(payload: &[u8], signature: &str, pub_key_bytes: &[u8]) -> Result<(), Error> {
    let sig_bytes = hex::decode(signature).map_err(|_| Error::SignatureFormatError)?;
    let secp = Secp256k1::new();
    let msg = Message::from_hashed_data::<sha256::Hash>(payload);
    let sig = Signature::from_der(&sig_bytes).map_err(Error::Secp256k1Error)?;
    let pk = PublicKey::from_slice(pub_key_bytes).map_err(Error::Secp256k1Error)?;
    secp.verify_ecdsa(&msg, &sig, &pk)
        .map_err(|_| Error::InvalidSignature)
}

/// Verifies the signature on a uma pay request based on the public key of the VASP making the request.
///
/// # Arguments
///
/// * `pay_req` - the signed query to verify.
/// * `other_vasp_pub_key` - the bytes of the signing public key of the VASP making this request.
pub fn verify_pay_req_signature(
    pay_req: &PayRequest,
    other_vasp_pub_key_response: &PubKeyResponse,
    nonce_cache: &mut dyn NonceCache,
) -> Result<(), Error> {
    let compliance_data = pay_req
        .payer_data
        .clone()
        .and_then(|payer_data| payer_data.compliance().ok())
        .flatten()
        .ok_or(Error::InvalidPayerData)?;
    nonce_cache
        .check_and_save_nonce(
            &compliance_data.signature_nonce,
            compliance_data.signature_timestamp,
        )
        .map_err(|_| Error::NonceError)?;
    let payload = pay_req.signable_payload().map_err(Error::ProtocolError)?;
    verify_ecdsa(
        &payload,
        &compliance_data.signature,
        &other_vasp_pub_key_response
            .signing_pubkey()
            .map_err(Error::ProtocolError)?,
    )
}

/// Creates a signed uma request URL.
///
/// # Arguments
///
/// * `signing_private_key` - the private key of the VASP that is sending the payment. This will be used to sign the request.
/// * `receiver_address` - the address of the receiver of the payment (i.e. $bob@vasp2).
/// * `sender_vasp_domain` - the domain of the VASP that is sending the payment. It will be used by the receiver to fetch the public keys of the sender.
/// * `is_subject_to_travel_rule` - whether the sending VASP is a financial institution that requires travel rule information.
/// * `uma_version_override` - the version of the UMA protocol to use. If not specified, the latest version will be used.
pub fn get_signed_lnurlp_request_url(
    signing_private_key: &[u8],
    receiver_address: &str,
    sender_vasp_domain: &str,
    is_subject_to_travel_rule: bool,
    uma_version_override: Option<&str>,
) -> Result<url::Url, Error> {
    let nonce = generate_nonce();
    let uma_version = match uma_version_override {
        Some(version) => version.to_string(),
        None => version::uma_protocol_version(),
    };
    let mut unsigned_request = LnurlpRequest {
        receiver_address: receiver_address.to_owned(),
        nonce: Some(nonce),
        timestamp: Some(chrono::Utc::now().timestamp()),
        signature: None,
        vasp_domain: Some(sender_vasp_domain.to_owned()),
        is_subject_to_travel_rule: Some(is_subject_to_travel_rule),
        uma_version: Some(uma_version),
    };

    let sig = sign_payload(
        &unsigned_request
            .signable_payload()
            .map_err(Error::ProtocolError)?,
        signing_private_key,
    )?;
    unsigned_request.signature = Some(sig);

    unsigned_request
        .encode_to_url()
        .map_err(Error::ProtocolError)
}

/// Checks if the given URL is a valid UMA request.
pub fn is_uma_lnurl_query(url: &url::Url) -> bool {
    parse_lnurlp_request(url).is_ok_and(|req| req.as_uma_lnurlp_request().is_some())
}

/// Parses the message into an LnurlpRequest object.
///
/// # Arguments
/// * `url` - the full URL of the uma request.
pub fn parse_lnurlp_request(url: &url::Url) -> Result<LnurlpRequest, Error> {
    let mut query = url.query_pairs();
    let signature = query
        .find(|(key, _)| key == "signature")
        .map(|(_, value)| value.to_string());

    let mut query = url.query_pairs();
    let vasp_domain = query
        .find(|(key, _)| key == "vaspDomain")
        .map(|(_, value)| value.to_string());

    let mut query = url.query_pairs();
    let nonce = query
        .find(|(key, _)| key == "nonce")
        .map(|(_, value)| value.to_string());

    let mut query = url.query_pairs();
    let is_subject_to_travel_rule = query
        .find(|(key, _)| key == "isSubjectToTravelRule")
        .map(|(_, value)| value.to_lowercase() == "true");

    let mut query = url.query_pairs();
    let timestamp = query
        .find(|(key, _)| key == "timestamp")
        .map(|(_, value)| value.parse::<i64>())
        .transpose()
        .map_err(|_| Error::MissingUrlParam("timestamp".to_string()))?;

    let mut query = url.query_pairs();
    let uma_version = query
        .find(|(key, _)| key == "umaVersion")
        .map(|(_, value)| value)
        .ok_or(Error::MissingUrlParam("umaVersion".to_string()))?;

    let path_parts: Vec<&str> = url.path_segments().ok_or(Error::InvalidUrlPath)?.collect();
    if path_parts.len() != 3 || path_parts[0] != ".well-known" || path_parts[1] != "lnurlp" {
        return Err(Error::InvalidUrlPath);
    }

    if !is_version_supported(&uma_version) {
        return Err(Error::UnsupportedVersion(UnsupportedVersionError {
            unsupported_version: uma_version.to_string(),
            supported_major_versions: version::get_supported_major_version(),
        }));
    }

    let receiver_address = format!(
        "{}@{}",
        path_parts[2],
        url.host_str().ok_or(Error::InvalidHost)?
    );

    Ok(LnurlpRequest {
        receiver_address,
        vasp_domain,
        signature,
        nonce,
        timestamp,
        is_subject_to_travel_rule,
        uma_version: Some(uma_version.to_string()),
    })
}

/// Verifies the signature on an uma Lnurlp query based on the public key of the VASP making the request.
///
/// # Arguments
/// * `query` - the signed query to verify.
/// * `other_vasp_pub_key` - the bytes of the signing public key of the VASP making this request.
pub fn verify_uma_lnurlp_query_signature(
    query: UmaLnurlpRequest,
    other_vasp_pub_key_response: &PubKeyResponse,
    nonce_cache: &mut dyn NonceCache,
) -> Result<(), Error> {
    nonce_cache
        .check_and_save_nonce(&query.nonce, query.timestamp)
        .map_err(|_| Error::NonceError)?;
    verify_ecdsa(
        &query.signable_payload(),
        &query.signature,
        &other_vasp_pub_key_response
            .signing_pubkey()
            .map_err(Error::ProtocolError)?,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn get_lnurlp_response(
    query: &LnurlpRequest,
    private_key_bytes: &[u8],
    requires_travel_rule_info: bool,
    callback: &str,
    encoded_metadata: &str,
    min_sendable_sats: i64,
    max_sendable_sats: i64,
    payer_data_options: &CounterPartyDataOptions,
    currency_options: &[Currency],
    receiver_kyc_status: KycStatus,
    comment_chars_allowed: Option<i64>,
    nostr_pubkey: Option<String>,
) -> Result<LnurlpResponse, Error> {
    // TODO: nil fields
    let compliance_response = get_signed_compliance_respionse(
        query,
        private_key_bytes,
        requires_travel_rule_info,
        receiver_kyc_status,
    )?;
    let uma_version = version::select_lower_version(
        &query.uma_version.clone().ok_or(Error::InvalidVersion)?,
        &version::uma_protocol_version(),
    )
    .map_err(|_| Error::InvalidVersion)?;

    let mut allows_nostr: Option<bool> = None;
    if nostr_pubkey.is_some() {
        allows_nostr = Some(true);
    }

    Ok(LnurlpResponse {
        tag: "payRequest".to_string(),
        callback: callback.to_string(),
        min_sendable: min_sendable_sats * 1000,
        max_sendable: max_sendable_sats * 1000,
        encoded_metadata: encoded_metadata.to_string(),
        currencies: Some(currency_options.to_vec()),
        required_payer_data: Some(payer_data_options.clone()),
        compliance: Some(compliance_response.clone()),
        uma_version: Some(uma_version.clone()),
        comment_chars_allowed,
        nostr_pubkey,
        allows_nostr,
    })
}

fn get_signed_compliance_respionse(
    query: &LnurlpRequest,
    private_key_bytes: &[u8],
    is_subject_to_travel_rule: bool,
    receiver_kyc_status: KycStatus,
) -> Result<LnurlComplianceResponse, Error> {
    let timestamp = chrono::Utc::now().timestamp();
    let nonce = generate_nonce();
    let payload_string = format!("{}|{}|{}", query.receiver_address, nonce, timestamp);

    let signature = sign_payload(payload_string.as_bytes(), private_key_bytes)?;

    Ok(LnurlComplianceResponse {
        kyc_status: receiver_kyc_status,
        signature,
        nonce,
        timestamp,
        is_subject_to_travel_rule,
        receiver_identifier: query.receiver_address.clone(),
    })
}

/// Verifies the signature on an uma Lnurlp response based on the public key of the VASP making the request.
///
/// # Arguments
/// * `response` - the signed response to verify.
/// * `other_vasp_pub_key` - the bytes of the signing public key of the VASP making this request.
pub fn verify_uma_lnurlp_response_signature(
    response: &LnurlpResponse,
    other_vasp_pub_key_response: &PubKeyResponse,
    nonce_cache: &mut dyn NonceCache,
) -> Result<(), Error> {
    let compliance = response
        .as_uma_response()
        .ok_or(Error::InvalidResponse)?
        .compliance;
    nonce_cache
        .check_and_save_nonce(&compliance.nonce, compliance.timestamp)
        .map_err(|_| Error::NonceError)?;

    let uma_response = response.as_uma_response().ok_or(Error::InvalidResponse)?;
    let payload = uma_response.signable_payload();
    verify_ecdsa(
        &payload,
        &uma_response.compliance.signature,
        &other_vasp_pub_key_response
            .signing_pubkey()
            .map_err(Error::ProtocolError)?,
    )
}

pub fn parse_lnurlp_response(bytes: &[u8]) -> Result<LnurlpResponse, Error> {
    serde_json::from_slice(bytes).map_err(Error::InvalidData)
}

/// Gets the domain of the VASP from an uma address.
pub fn get_vasp_domain_from_uma_address(uma_address: &str) -> Result<String, Error> {
    let address_parts: Vec<&str> = uma_address.split('@').collect();
    if address_parts.len() != 2 {
        Err(Error::InvalidUMAAddress)
    } else {
        Ok(address_parts[1].to_string())
    }
}

/// Creates a signed uma pay request.
///
/// # Arguments
/// * `receiver_encryption_pub_key` - the public key of the receiver of the payment. This will be used to encrypt the travel rule information.
/// * `sending_vasp_private_key` - the private key of the VASP that is sending the payment. This will be used to sign the request.
/// * `currency_code` - the currency code of the payment.
/// * `amount` - the amount of the payment in the smallest unit of the specified currency (i.e. cents for USD).
/// * `payer_identifier` - the identifier of the sender. For example, $alice@vasp1.com
/// * `payer_name` - the name of the sender.
/// * `payer_email` - the email of the sender.
/// * `tr_info` - the travel rule information to be encrypted.
/// * `travel_rule_format` - the format of the travel rule information (e.g. IVMS). Null indicates
///     raw json or a custom format. This field is formatted as <standardized format>@<version>
///     (e.g. ivms@101.2023). Version is optional.
/// * `payer_kyc_status` - the KYC status of the sender.
/// * `payer_uxtos` - the list of UTXOs of the sender's channels that might be used to fund the payment.
/// * `payer_node_pubkey` - If known, the public key of the sender's node. If supported by the receiving VASP's compliance provider, this will be used to pre-screen the sender's UTXOs for compliance purposes.
/// * `utxo_callback` - the URL that the receiver will use to fetch the sender's UTXOs.
#[allow(clippy::too_many_arguments)]
pub fn get_pay_request(
    amount: i64,
    receiver_encryption_pub_key: &[u8],
    sending_vasp_private_key: &[u8],
    receving_currency_code: &str,
    is_amount_in_receving_currency_code: bool,
    payer_identifier: &str,
    uma_major_version: i32,
    payer_name: Option<&str>,
    payer_email: Option<&str>,
    tr_info: Option<&str>,
    travel_rule_format: Option<TravelRuleFormat>,
    payer_kyc_status: KycStatus,
    payer_uxtos: &[String],
    payer_node_pubkey: Option<&str>,
    utxo_callback: &str,
    requested_payee_data: Option<CounterPartyDataOptions>,
    comment: Option<&str>,
) -> Result<PayRequest, Error> {
    let compliance_data = get_signed_compliance_payer_data(
        receiver_encryption_pub_key,
        sending_vasp_private_key,
        payer_identifier,
        tr_info,
        travel_rule_format,
        payer_kyc_status,
        payer_uxtos,
        payer_node_pubkey,
        utxo_callback,
    )?;

    let sending_amount_currency_code = if is_amount_in_receving_currency_code {
        Some(receving_currency_code.to_string())
    } else {
        None
    };

    let payer_data = PayerData(serde_json::json!({
        "identifier": payer_identifier,
        "name": payer_name,
        "email": payer_email,
        "compliance": compliance_data,
    }));
    Ok(PayRequest {
        sending_amount_currency_code,
        receiving_currency_code: Some(receving_currency_code.to_string()),
        payer_data: Some(payer_data),
        comment: comment.map(|s| s.to_string()),
        uma_major_version,
        amount,
        requested_payee_data,
    })
}

#[allow(clippy::too_many_arguments)]
fn get_signed_compliance_payer_data(
    receiver_encryption_pub_key: &[u8],
    sending_vasp_private_key: &[u8],
    payer_identifier: &str,
    tr_info: Option<&str>,
    travel_rule_format: Option<TravelRuleFormat>,
    payer_kyc_status: KycStatus,
    payer_uxtos: &[String],
    payer_node_pubkey: Option<&str>,
    utxo_callback: &str,
) -> Result<CompliancePayerData, Error> {
    let timestamp = chrono::Utc::now().timestamp();
    let nonce = generate_nonce();

    let encrypted_tr_info = match tr_info {
        Some(tr_info) => Some(encrypt_tr_info(tr_info, receiver_encryption_pub_key)?),
        None => None,
    };
    let payload_string = format!("{}|{}|{}", payer_identifier, nonce, timestamp);
    let signature = sign_payload(payload_string.as_bytes(), sending_vasp_private_key)?;

    Ok(CompliancePayerData {
        utxos: payer_uxtos.to_vec(),
        node_pubkey: payer_node_pubkey.map(|s| s.to_string()),
        kyc_status: payer_kyc_status,
        encrypted_travel_rule_info: encrypted_tr_info,
        travel_rule_format,
        signature,
        signature_nonce: nonce,
        signature_timestamp: timestamp,
        utxo_callback: utxo_callback.to_string(),
    })
}

fn encrypt_tr_info(tr_info: &str, receiver_encryption_pub_key: &[u8]) -> Result<String, Error> {
    let cipher_text = ecies::encrypt(receiver_encryption_pub_key, tr_info.as_bytes())
        .map_err(Error::EciesSecp256k1Error)?;
    Ok(hex::encode(cipher_text))
}

pub fn parse_pay_request(bytes: &[u8]) -> Result<PayRequest, Error> {
    serde_json::from_slice(bytes).map_err(Error::InvalidData)
}

pub trait InvoiceCreator {
    fn create_invoice(
        &self,
        amount_msat: i64,
        metadata: &str,
    ) -> Result<String, Box<dyn std::error::Error>>;
}

#[allow(clippy::too_many_arguments)]
pub fn get_pay_req_response<T>(
    request: &PayRequest,
    invoice_creator: &T,
    metadata: &str,
    receiving_currency_code: Option<&str>,
    receiving_currency_decimals: Option<i32>,
    conversion_rate: Option<f64>,
    receiver_fees_millisats: Option<i64>,
    receiver_channel_utxos: Option<&[String]>,
    receiver_node_pub_key: Option<&str>,
    utxo_callback: Option<&str>,
    payee_data: Option<&PayeeData>,
    receiving_vasp_private_key: Option<Vec<u8>>,
    payee_identifier: Option<&str>,
    disposable: Option<bool>,
    success_action: Option<HashMap<String, String>>,
) -> Result<PayReqResponse, Error>
where
    T: InvoiceCreator,
{
    if request.sending_amount_currency_code.is_some()
        && request.sending_amount_currency_code != request.receiving_currency_code
    {
        return Err(Error::UnsupportedCurrency);
    }
    validate_pay_req_currency_fields(
        receiving_currency_code,
        receiving_currency_decimals,
        conversion_rate,
        receiver_fees_millisats,
    )?;

    let rate = conversion_rate.unwrap_or(1.0);

    let fee = receiver_fees_millisats.unwrap_or(0);

    let amount = match (
        receiving_currency_code,
        &request.sending_amount_currency_code,
    ) {
        (Some(_), Some(_)) => ((request.amount as f64) * rate) as i64 + fee,
        _ => request.amount,
    };

    let payer_data_str = match &request.payer_data {
        Some(data) => serde_json::to_string(&data).map_err(Error::InvalidData)?,
        None => "".to_string(),
    };

    let metadata_str = format!("{}{}", metadata, payer_data_str);
    let encoded_invoice = invoice_creator
        .create_invoice(amount, &metadata_str)
        .map_err(|err| Error::CreateInvoiceError(err.to_string()))?;

    let payee_data = match (
        request.is_uma_request(),
        payee_data.is_some_and(|data| data.compliance().is_ok_and(|c| c.is_some())),
    ) {
        (true, false) => {
            validate_uma_pay_req_fields(
                receiving_currency_code,
                receiving_currency_decimals,
                conversion_rate,
                receiver_fees_millisats,
                receiver_channel_utxos,
                receiver_node_pub_key,
                payee_identifier,
                receiving_vasp_private_key.as_deref(),
            )?;

            let payer_identifier = request
                .payer_data
                .as_ref()
                .expect("UMA request has non-nil payer_data")
                .identifier();

            let utxos = match receiver_channel_utxos {
                Some(utxos) => utxos.to_vec(),
                None => vec![],
            };

            let complince_data = get_signed_compliance_payee_data(
                &receiving_vasp_private_key.expect("Validated"),
                payer_identifier.expect("Validated"),
                payee_identifier.expect("Validated"),
                &utxos,
                receiver_node_pub_key,
                utxo_callback,
            )?;

            match payee_data {
                Some(data) => {
                    let mut map = match &data.0 {
                        serde_json::Value::Object(map) => map.clone(),
                        _ => return Err(Error::InvalidPayeeData),
                    };
                    map.insert(
                        CounterPartyDataField::CounterPartyDataFieldCompliance.to_string(),
                        serde_json::to_value(complince_data).map_err(Error::InvalidData)?,
                    );
                    Some(PayeeData(serde_json::Value::Object(map.clone())))
                }
                None => Some(PayeeData(serde_json::json!({
                    CounterPartyDataField::CounterPartyDataFieldIdentifier.to_string(): payee_identifier,
                    CounterPartyDataField::CounterPartyDataFieldCompliance.to_string(): complince_data
                }))),
            }
        }
        (_, _) => payee_data.cloned(),
    };

    let receiving_currency_amount = match (
        request.uma_major_version,
        &request.sending_amount_currency_code,
    ) {
        (0, _) => None,
        (_, Some(_)) => Some(((amount - fee) as f64 / rate) as i64),
        (_, None) => Some(request.amount),
    };

    let payment_info = receiving_currency_code.map(|code| PayReqResponsePaymentInfo {
        amount: receiving_currency_amount,
        currency_code: code.to_string(),
        decimals: receiving_currency_decimals.expect("Validated"),
        multiplier: conversion_rate.expect("Validated"),
        exchange_fees_millisatoshi: receiver_fees_millisats.expect("Validated"),
    });

    Ok(PayReqResponse {
        success_action,
        disposable,
        payment_info,
        encoded_invoice,
        routes: vec![],
        payee_data,
        uma_major_version: request.uma_major_version,
    })
}

fn validate_pay_req_currency_fields(
    receiving_currency_code: Option<&str>,
    receiving_currency_decimals: Option<i32>,
    conversion_rate: Option<f64>,
    receiver_fees_millisats: Option<i64>,
) -> Result<(), Error> {
    let mut num_nil_fields = 0;
    if receiving_currency_code.is_none() {
        num_nil_fields += 1;
    }
    if receiving_currency_decimals.is_none() {
        num_nil_fields += 1;
    }
    if conversion_rate.is_none() {
        num_nil_fields += 1;
    }
    if receiver_fees_millisats.is_none() {
        num_nil_fields += 1;
    }
    if num_nil_fields != 0 && num_nil_fields != 4 {
        return Err(Error::InvalidCurrencyFields);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_uma_pay_req_fields(
    receiving_currency_code: Option<&str>,
    receiving_currency_decimals: Option<i32>,
    conversion_rate: Option<f64>,
    receiver_fees_millisats: Option<i64>,
    receiver_channel_utxos: Option<&[String]>,
    receiver_node_pub_key: Option<&str>,
    payee_identifier: Option<&str>,
    signing_private_key: Option<&[u8]>,
) -> Result<(), Error> {
    if receiving_currency_code.is_none()
        || receiving_currency_decimals.is_none()
        || conversion_rate.is_none()
        || receiver_fees_millisats.is_none()
    {
        return Err(Error::MissingUmaField("currency fields".to_string()));
    }

    if payee_identifier.is_none() {
        return Err(Error::MissingUmaField("payee_identifier".to_string()));
    }

    if signing_private_key.is_none() {
        return Err(Error::MissingUmaField("signing_private_key".to_string()));
    }

    if receiver_channel_utxos.is_none() && receiver_node_pub_key.is_none() {
        return Err(Error::MissingUmaField(
            "receiver_channel_utxos and/or receiver_node_pub_key".to_string(),
        ));
    }
    Ok(())
}

fn get_signed_compliance_payee_data(
    receiving_vasp_private_key: &[u8],
    payer_identifier: &str,
    payee_identifier: &str,
    receiver_channel_utxos: &[String],
    receiver_node_pub_key: Option<&str>,
    utxo_callback: Option<&str>,
) -> Result<CompliancePayeeData, Error> {
    let timestamp = chrono::Utc::now().timestamp();
    let nonce = generate_nonce();
    let mut builder = CompliancePayeeDataBuilder::new()
        .utxos(receiver_channel_utxos.to_vec())
        .node_pubkey(receiver_node_pub_key.map(|s| s.to_string()))
        .utxo_callback(utxo_callback.map(|s| s.to_string()))
        .signature_nonce(Some(nonce))
        .signature_timestamp(Some(timestamp));
    let signable_payload = builder
        .build()
        .signable_payload(payer_identifier, payee_identifier)
        .map_err(Error::ProtocolError)?;
    let signature = sign_payload(&signable_payload, receiving_vasp_private_key)?;
    builder = builder.signature(Some(signature));
    Ok(builder.build())
}

pub fn parse_pay_req_response(bytes: &[u8]) -> Result<PayReqResponse, Error> {
    serde_json::from_slice(bytes).map_err(Error::InvalidData)
}

pub fn verify_pay_req_response_signature(
    response: &PayReqResponse,
    other_vasp_pub_key_response: &PubKeyResponse,
    nonce_cache: &mut dyn NonceCache,
    payer_identifier: &str,
    payee_identifier: &str,
) -> Result<(), Error> {
    let compliance_data = response
        .payee_data
        .clone()
        .ok_or(Error::InvalidPayeeData)?
        .compliance()
        .map_err(Error::ProtocolError)?
        .ok_or(Error::InvalidPayeeData)?;

    if response.uma_major_version == 0 {
        return Err(Error::UnsupportedUmaVersion(response.uma_major_version, 1));
    }

    nonce_cache
        .check_and_save_nonce(
            &compliance_data.signature_nonce.clone().expect("Rquired"),
            compliance_data.signature_timestamp.expect("Required"),
        )
        .map_err(|_| Error::NonceError)?;

    let signable_payload = compliance_data
        .signable_payload(payer_identifier, payee_identifier)
        .map_err(Error::ProtocolError)?;

    verify_ecdsa(
        &signable_payload,
        &compliance_data.signature.expect("Required"),
        &other_vasp_pub_key_response
            .signing_pubkey()
            .map_err(Error::ProtocolError)?,
    )
}

// get_post_transaction_callback Creates a signed post transaction callback.
//
// Args:
//
//	utxos: UTXOs of the channels of the VASP initiating the callback.
//	vasp_domain: the domain of the VASP initiating the callback.
//	signing_private_key: the private key of the VASP initiating the callback. This will be used to sign the request.
pub fn get_post_transaction_callback(
    utxos: &[UtxoWithAmount],
    vasp_domain: &str,
    signing_private_key: &[u8],
) -> Result<PostTransactionCallback, Error> {
    let nonce = generate_nonce();
    let timestamp = chrono::Utc::now().timestamp();
    let mut builder = PostTransactionCallbackBuilder::default();
    builder = builder
        .utxos(utxos.to_vec())
        .vasp_domain(vasp_domain.to_string())
        .nonce(nonce)
        .timestamp(timestamp);
    let signable_payload = builder
        .build()
        .signable_payload()
        .map_err(Error::ProtocolError)?;
    let signature = sign_payload(&signable_payload, signing_private_key)?;
    builder = builder.signature(signature);
    Ok(builder.build())
}

pub fn parse_post_transaction_callback(bytes: &[u8]) -> Result<PostTransactionCallback, Error> {
    serde_json::from_slice(bytes).map_err(Error::InvalidData)
}

// verify_post_transaction_callback_signature Verifies the signature on a post transaction callback based on the
// public key of the counterparty VASP.
//
// Args:
//
//	callback: the signed callback to verify.
//	other_vasp_pub_key_response: the PubKeyResponse of the VASP making this request.
//	nonce_cache: the NonceCache cache to use to prevent replay attacks.
pub fn verify_post_transaction_callback_signature(
    callback: &PostTransactionCallback,
    other_vasp_pub_key_response: &PubKeyResponse,
    nonce_cache: &mut dyn NonceCache,
) -> Result<(), Error> {
    if callback.signature.is_none() || callback.nonce.is_none() || callback.timestamp.is_none() {
        return Err(Error::UnsupportedUmaVersion(0, 1));
    }
    nonce_cache
        .check_and_save_nonce(
            &callback.nonce.clone().expect("Required"),
            callback.timestamp.expect("Required"),
        )
        .map_err(|_| Error::NonceError)?;
    let payload = callback.signable_payload().map_err(Error::ProtocolError)?;
    verify_ecdsa(
        &payload,
        &callback.signature.clone().expect("Required"),
        &other_vasp_pub_key_response
            .signing_pubkey()
            .map_err(Error::ProtocolError)?,
    )
}
