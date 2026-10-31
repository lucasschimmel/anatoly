//! Certificate metadata from the already validated HTTP TLS connection.
use crate::{http::display_url, ui::safe_text};
use reqwest::{Url, tls::TlsInfo};
use serde::Serialize;
use x509_parser::prelude::{FromDer, X509Certificate};

const MAX_CERTIFICATE_BYTES: usize = 131_072;
const MAX_NAME_CHARACTERS: usize = 256;
const LIMITATION: &str = "Metadata describes the peer of this validated connection, which can be a configured TLS proxy or edge rather than the PHP origin. Revocation and support for every TLS protocol/cipher were not audited. The native TLS backend does not report the negotiated protocol.";

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TlsObservation {
    pub source: String,
    pub status: String,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before_unix: Option<i64>,
    pub not_after_unix: Option<i64>,
    pub protocol: Option<String>,
    pub limitation: String,
}

/// This function never opens a connection or weakens certificate validation.
pub fn inspect(url: &Url, tls: Option<&TlsInfo>) -> TlsObservation {
    let mut result = TlsObservation {
        source: display_url(url),
        status: "unavailable".into(),
        subject: None,
        issuer: None,
        not_before_unix: None,
        not_after_unix: None,
        protocol: tls.and_then(TlsInfo::version).map(|v| format!("{v:?}")),
        limitation: LIMITATION.into(),
    };
    let Some(bytes) = tls.and_then(TlsInfo::peer_certificate) else {
        return result;
    };
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        result
            .limitation
            .push_str(" Certificate metadata exceeded the parser input limit.");
        return result;
    }
    let Ok((remaining, certificate)) = X509Certificate::from_der(bytes) else {
        result
            .limitation
            .push_str(" The leaf certificate could not be decoded for display.");
        return result;
    };
    if !remaining.is_empty() {
        result
            .limitation
            .push_str(" Unexpected trailing certificate bytes prevented metadata decoding.");
        return result;
    }
    result.status = "observed".into();
    result.subject = Some(bounded_name(&certificate.subject().to_string()));
    result.issuer = Some(bounded_name(&certificate.issuer().to_string()));
    result.not_before_unix = Some(certificate.validity().not_before.timestamp());
    result.not_after_unix = Some(certificate.validity().not_after.timestamp());
    result
}

fn bounded_name(value: &str) -> String {
    safe_text(value).chars().take(MAX_NAME_CHARACTERS).collect()
}
