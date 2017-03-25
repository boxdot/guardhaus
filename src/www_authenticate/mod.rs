//! An implementation of the `WWW-Authenticate` header.

use hyper::header::Header;
use hyper::header::parsing::from_one_raw_str;
use hyper::{Error as HyperError, Result as HyperResult};
use parsing::{parse_parameters, unraveled_map_value};
use super::types::{HashAlgorithm, Qop};
use unicase::UniCase;

use std::collections::HashMap;
use std::str::FromStr;
use std::iter::FromIterator;

mod test;

/// Parameters for the `WWW-Authenticate` header of a server response
///
/// The parameters are described in more detail in
/// [RFC 2069](https://tools.ietf.org/html/rfc2069#section-2.1.1), and
/// [RFC 7616](https://tools.ietf.org/html/rfc7616#section-3.3).
/// Unless otherwise noted, the parameter name maps to the struct variable name.
#[derive(Clone, PartialEq, Debug)]
pub struct WwwAuthenticate {
    /// Authentication realm.
    pub realm: String,
    /// Optional comma-separated list of URIs
    pub domain: Vec<String>,
    /// Cryptographic nonce.
    pub nonce: String,
    /// Optional opaque string.
    pub opaque: Option<String>,
    /// Whether `request` from the client was rejected because the nonce value was stale.
    pub stale: bool,
    /// The hash algorithm to use when generating the `response`.
    pub algorithm: HashAlgorithm,
    /// Quality of protection. Optional only in RFC 2067 mode.
    pub qop: Option<Qop>,
    /// The character set to use when generating the A1 value or the userhash. Added for RFC 7616.
    pub charset: Option<String>,
    /// Whether `username` is a userhash. Added for RFC 7616.
    pub userhash: bool,
}

fn parse_domain(parameters: &HashMap<UniCase<String>, String>) -> Vec<String> {
    match unraveled_map_value(parameters, "domain") {
        Some(value) => Vec::from_iter(value.split(",").map(str::trim).map(String::from)),
        None => vec![],
    }
}

fn parse_bool(parameters: &HashMap<UniCase<String>, String>,
              name: &str)
              -> Result<bool, HyperError> {
    let value = unraveled_map_value(parameters, name);
    match value {
        Some(s) => {
            match &s[..] {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(HyperError::Header),
            }
        }
        None => Ok(false),
    }
}

impl FromStr for WwwAuthenticate {
    type Err = HyperError;

    fn from_str(s: &str) -> Result<WwwAuthenticate, HyperError> {
        let parameters = parse_parameters(s);
        let realm = match unraveled_map_value(&parameters, "realm") {
            Some(value) => value,
            None => return Err(HyperError::Header),
        };
        let domain = parse_domain(&parameters);
        let nonce = match unraveled_map_value(&parameters, "nonce") {
            Some(value) => value,
            None => return Err(HyperError::Header),
        };
        let opaque = unraveled_map_value(&parameters, "opaque");
        let stale: bool = parse_bool(&parameters, "stale")?;
        let algorithm = match unraveled_map_value(&parameters, "algorithm") {
            Some(s) => HashAlgorithm::from_str(&s)?,
            None => HashAlgorithm::MD5,
        };
        let qop = Qop::from_parameters(&parameters)?;
        let charset = unraveled_map_value(&parameters, "charset");
        let userhash = parse_bool(&parameters, "userhash")?;

        Ok(WwwAuthenticate {
            realm: realm,
            domain: domain,
            nonce: nonce,
            opaque: opaque,
            stale: stale,
            algorithm: algorithm,
            qop: qop,
            charset: charset,
            userhash: userhash,
        })
    }
}


impl Header for WwwAuthenticate {
    fn header_name() -> &'static str {
        "WWW-Authenticate"
    }

    fn parse_header(raw: &[Vec<u8>]) -> HyperResult<WwwAuthenticate> {
        from_one_raw_str(raw).and_then(|s: String| WwwAuthenticate::from_str(&s[..]))
    }
}
