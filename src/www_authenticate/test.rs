#![cfg(test)]

use parsing::test_helper::assert_parsed_header_equal;
use super::WwwAuthenticate;
use super::super::types::{HashAlgorithm, Qop};

#[test]
fn test_parse_authentication_info_with_digest_and_nextnonce() {
    let expected = WwwAuthenticate {
        realm: "testrealm@host.com".to_owned(),
        domain: vec![],
        nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_owned(),
        opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_owned()),
        stale: false,
        algorithm: HashAlgorithm::MD5,
        qop: None,
        charset: None,
        userhash: false,
    };
    assert_parsed_header_equal(expected,
                               "realm=\"testrealm@host.com\", \
                                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");
}

#[test]
/// TODO: fix qop
fn test_parse_www_authenticate_rfc7616_3_9_1_shasum() {
    let expected = WwwAuthenticate {
        realm: "http-auth@example.org".to_owned(),
        domain: vec![],
        nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v".to_owned(),
        opaque: Some("FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS".to_owned()),
        stale: false,
        algorithm: HashAlgorithm::SHA256,
        qop: Some(Qop::Auth),
        charset: None,
        userhash: false,
    };
    assert_parsed_header_equal(expected,
                               "realm=\"http-auth@example.org\", qop=\"auth, auth-int\", \
                                algorithm=SHA-256, \
                                nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
                                opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"")
}

/// Cf. https://tools.ietf.org/html/rfc7616#section-3.9.1
/// TODO: fix qop
#[test]
fn test_parse_www_authenticate_rfc7616_3_9_1_md5() {
    let expected = WwwAuthenticate {
        realm: "http-auth@example.org".to_owned(),
        domain: vec![],
        nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v".to_owned(),
        opaque: Some("FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS".to_owned()),
        stale: false,
        algorithm: HashAlgorithm::MD5,
        qop: Some(Qop::Auth),
        charset: None,
        userhash: false,
    };
    assert_parsed_header_equal(expected,
                               "realm=\"http-auth@example.org\", qop=\"auth, auth-int\", \
                                algorithm=MD5, \
                                nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
                                opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"")
}

/// Cf. https://tools.ietf.org/html/rfc7616#section-3.9.2
#[test]
fn test_parse_www_authenticate_rfc7616_3_9_2() {
    let expected = WwwAuthenticate {
        realm: "api@example.org".to_owned(),
        domain: vec![],
        nonce: "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK".to_owned(),
        opaque: Some("HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS".to_owned()),
        stale: false,
        algorithm: HashAlgorithm::SHA512256,
        qop: Some(Qop::Auth),
        charset: Some("UTF-8".to_owned()),
        userhash: true,
    };
    assert_parsed_header_equal(expected,
                               "realm=\"api@example.org\", qop=\"auth\", algorithm=SHA-512-256, \
                                nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", \
                                opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\", \
                                charset=UTF-8, userhash=true")
}
