// Copyright 2016 Hroi Sigurdsson
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # RUST-SNMP
//! Dependency-free basic SNMPv2 client in Rust.
//!
//! Suppports:
//!
//! - GET
//! - GETNEXT
//! - GETBULK
//! - SET
//! - Basic SNMPv2 types
//! - Synchronous requests
//! - UDP transport
//! - SNMPv3
//! - Async requests
//! - Walking function
//!
//! Currently does not support:
//!
//! - MIBs
//! - Transports other than UDP
//!
//! ## TODO
//! - Additional `ObjectIdentifier` utility methods
//!

//! # Examples
//!
//! ## GET NEXT
//! ```no_run
//! use std::time::Duration;
//! use snmp::{SyncSession, SnmpSecurity, Value};
//!
//! let sys_descr_oid = &[1,3,6,1,2,1,1,1,];
//! let agent_addr    = "198.51.100.123:161";
//! let security      = SnmpSecurity::from_bytes(0,b"f00b4r");
//! let timeout       = Duration::from_secs(2);
//!
//! let mut sess = SyncSession::new(agent_addr, security, Some(timeout), 1).unwrap();
//! let mut response = sess.getnext(sys_descr_oid, 1).unwrap();
//! if let Some((_oid, Value::OctetString(sys_descr))) = response.varbinds.next() {
//!     println!("myrouter sysDescr: {}", String::from_utf8_lossy(sys_descr));
//! }
//! ```
//! ## GET BULK
//! ```no_run
//! use std::time::Duration;
//! use snmp::{SyncSession, SnmpSecurity};
//!
//! let system_oid      = &[1u32,3,6,1,2,1,1,];
//! let agent_addr      = "[2001:db8:f00:b413::abc]:161";
//! let security        = SnmpSecurity::from_bytes(0,b"f00b4r");
//! let timeout         = Duration::from_secs(2);
//! let non_repeaters   = 0;
//! let max_repetitions = 7; // number of items in "system" OID
//!
//! let mut sess = SyncSession::new(agent_addr, security, Some(timeout), 1).unwrap();
//! let response = sess.getbulk([system_oid], non_repeaters, max_repetitions).unwrap();
//!
//! for (name, val) in response.varbinds {
//!     println!("{} => {:?}", name, val);
//! }
//! ```
//! ## SET
//! ```no_run
//! use std::time::Duration;
//! use snmp::{SyncSession, SnmpSecurity, Value};
//!
//! let syscontact_oid  = &[1u32,3,6,1,2,1,1,4,0];
//! let contact         = Value::OctetString(b"Thomas A. Anderson");
//! let agent_addr      = "[2001:db8:f00:b413::abc]:161";
//! let security        = SnmpSecurity::from_bytes(0,b"f00b4r");
//! let timeout         = Duration::from_secs(2);
//!
//! let mut sess = SyncSession::new(agent_addr, security, Some(timeout), 1).unwrap();
//! let response = sess.set(&[(syscontact_oid, contact)], 1).unwrap();
//!
//! assert_eq!(response.error_status, snmp::snmp::ERRSTATUS_NOERROR);
//! for (name, val) in response.varbinds {
//!     println!("{} => {:?}", name, val);
//! }
//! ```

// #![cfg_attr(feature = "private-tests", feature(test))]
// #![allow(unknown_lints, doc_markdown)]
extern crate serde;
#[macro_use]
extern crate log;
// use std::num::ParseIntError;
use std::fmt;
// use std::str::FromStr;
use serde::{Deserialize, Serialize};
//use std::io;
use std::mem;
use std::ptr;

#[cfg(feature = "simpleasync")]
pub mod tokio_session;
#[cfg(feature = "async")]
pub mod tokio_socket;
#[cfg(feature = "stream")]
pub mod tokio_socket_utils;
#[cfg(feature = "v3")]
pub mod v3;

#[cfg(target_pointer_width = "32")]
const USIZE_LEN: usize = 4;
#[cfg(target_pointer_width = "64")]
const USIZE_LEN: usize = 8;

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
pub enum SnmpCredentials {
    V12 {
        version: u8,
        community: Vec<u8>,
    },
    #[cfg(feature = "v3")]
    V3(v3::Security),
}
impl SnmpCredentials {
    pub fn from_bytes(version: u8, community: &[u8]) -> SnmpCredentials {
        SnmpCredentials::V12 {
            version,
            community: community.to_vec(),
        }
    }
    pub fn new_v12(version: u8, community: Vec<u8>) -> SnmpCredentials {
        SnmpCredentials::V12 { version, community }
    }
    pub fn version(&self) -> u8 {
        match self {
            SnmpCredentials::V12 {
                version,
                community: _,
            } => *version,
            #[cfg(feature = "v3")]
            SnmpCredentials::V3(_) => 3,
        }
    }
    pub fn set_version(&mut self, ver: u8) -> SnmpResult<()> {
        match self {
            SnmpCredentials::V12 {
                version,
                community: _,
            } => {
                if ver >= 3 {
                    return Err(SnmpError::UnsupportedVersion);
                }
                *version = ver;
            }
            #[cfg(feature = "v3")]
            _ => {
                if ver != 3 {
                    return Err(SnmpError::UnsupportedVersion);
                }
            }
        };
        Ok(())
    }
    #[cfg(feature = "v3")]
    pub fn new_v3(security: v3::Security) -> SnmpCredentials {
        SnmpCredentials::V3(security)
    }
    #[cfg(feature = "v3")]
    pub fn v3(&self) -> Option<&v3::Security> {
        match self {
            SnmpCredentials::V12 {
                version: _,
                community: _,
            } => None,
            SnmpCredentials::V3(s) => Some(s),
        }
    }
}
impl std::str::FromStr for SnmpCredentials {
    type Err = SnmpError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("v1:") {
            return Ok(SnmpCredentials::new_v12(1, unescape_ascii(&s[3..])));
        }
        if s.starts_with("v2:") {
            return Ok(SnmpCredentials::new_v12(2, unescape_ascii(&s[3..])));
        }
        #[cfg(feature = "v3")]
        if s.starts_with("v3:") {
            return Ok(SnmpCredentials::new_v3(s[3..].parse()?));
        }
        return Ok(SnmpCredentials::new_v12(2, unescape_ascii(s)));
    }
}
impl std::fmt::Display for SnmpCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            SnmpCredentials::V12 { version, community } => {
                if *version != 2 {
                    write!(f, "v{}:", *version)?;
                }
                write!(f, "{}", community.escape_ascii())
            }
            #[cfg(feature = "v3")]
            SnmpCredentials::V3(s) => s.fmt(f),
        }
    }
}
#[derive(Debug)]
pub struct SnmpSecurity {
    pub credentials: SnmpCredentials,
    #[cfg(feature = "v3")]
    pub state: v3::SecurityState,
}
impl std::convert::From<SnmpCredentials> for SnmpSecurity {
    fn from(credentials: SnmpCredentials) -> SnmpSecurity {
        SnmpSecurity {
            credentials,
            #[cfg(feature = "v3")]
            state: Default::default(),
        }
    }
}
#[derive(Debug, PartialEq)]
pub enum SnmpError {
    AsnParseError,
    AsnInvalidLen,
    AsnWrongType,
    AsnUnsupportedType,
    AsnEof,
    AsnIntOverflow,

    UnsupportedVersion,
    RequestIdMismatch,
    CommunityMismatch,
    ValueOutOfRange,

    SendError(String),
    ReceiveError(String),
    Timeout,
    OidIsNotIncreasing,
    BufferOverflow,
    IoError(String),
    /// Authentication failure
    #[cfg(feature = "v3")]
    AuthFailure(v3::AuthErrorKind),
    /// OpenSSL errors
    #[cfg(feature = "v3")]
    Crypto(String),
    /// Security context has been updated, repeat the request
    #[cfg(feature = "v3")]
    AuthUpdated,
    ChannelOverflow,
}
impl fmt::Display for SnmpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SnmpError::AsnParseError => write!(f, "ASN Parse Error"),
            SnmpError::AsnInvalidLen => write!(f, "ASN Invalid length"),
            SnmpError::AsnWrongType => write!(f, "Wrong ASN Type"),
            SnmpError::AsnUnsupportedType => write!(f, "UnSupported ASN Type"),
            SnmpError::AsnEof => write!(f, "End of ASN"),
            SnmpError::AsnIntOverflow => write!(f, "ASN Overflow"),
            SnmpError::UnsupportedVersion => write!(f, "Unsupported Snmp Version"),
            SnmpError::RequestIdMismatch => write!(f, "SNMP Request ID mismatch"),
            SnmpError::CommunityMismatch => write!(f, "Community mismatch"),
            SnmpError::ValueOutOfRange => write!(f, "Value out of range"),
            SnmpError::SendError(s) => write!(f, "Snmp PDU Send Error({})", s),
            SnmpError::ReceiveError(s) => write!(f, "Snmp Receive Error({})", s),
            SnmpError::Timeout => write!(f, "Timeout"),
            SnmpError::OidIsNotIncreasing => write!(f, "OID is not increasing"),
            SnmpError::BufferOverflow => write!(f, "buffer overflow"),
            SnmpError::IoError(e) => write!(f, "io error ({})", e),
            #[cfg(feature = "v3")]
            SnmpError::AuthFailure(kind) => write!(f, "AuthFailure {}", kind),
            #[cfg(feature = "v3")]
            SnmpError::Crypto(arg) => write!(f, "Crypto {}", arg),
            #[cfg(feature = "v3")]
            SnmpError::AuthUpdated => write!(f, "AuthUpdated"),
            SnmpError::ChannelOverflow => write!(f, "Channel overflow"),
        }
    }
}

impl std::error::Error for SnmpError {
    fn description(&self) -> &str {
        match *self {
            SnmpError::AsnParseError => "ASN Parse Error",
            SnmpError::AsnInvalidLen => "ASN Invalid length",
            SnmpError::AsnWrongType => "Wrong ASN Type",
            SnmpError::AsnUnsupportedType => "UnSupported ASN Type",
            SnmpError::AsnEof => "End of ASN ",
            SnmpError::AsnIntOverflow => "ASN Overflow",
            SnmpError::UnsupportedVersion => "Unsupported Snmp Version",
            SnmpError::RequestIdMismatch => "SNMP Request ID mismatch",
            SnmpError::CommunityMismatch => "Community mismatch",
            SnmpError::ValueOutOfRange => "Value out of range",
            SnmpError::SendError(_) => "Snmp PDU Send Error",
            SnmpError::ReceiveError(_) => "Snmp Receive Error",
            SnmpError::Timeout => "Timeout",
            SnmpError::OidIsNotIncreasing => "OID is not increasing",
            SnmpError::BufferOverflow => "buffer overflow",
            SnmpError::IoError(_) => "IO error",
            #[cfg(feature = "v3")]
            SnmpError::AuthFailure(_) => "AuthFailure",
            #[cfg(feature = "v3")]
            SnmpError::Crypto(_) => "Crypto",
            #[cfg(feature = "v3")]
            SnmpError::AuthUpdated => "AuthUpdated",
            SnmpError::ChannelOverflow => "Channel overflow",
        }
    }
    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}

impl From<std::num::TryFromIntError> for SnmpError {
    fn from(_: std::num::TryFromIntError) -> SnmpError {
        SnmpError::AsnIntOverflow
    }
}
impl From<std::io::Error> for SnmpError {
    fn from(e: std::io::Error) -> SnmpError {
        SnmpError::IoError(format!("{}", e).to_string())
    }
}
pub type SnmpResult<T> = Result<T, SnmpError>;

pub const BUFFER_SIZE: usize = 4096;

pub mod asn1 {
    // #![allow(dead_code, identity_op, eq_op)]

    pub const PRIMITIVE: u8 = 0b00000000;
    pub const CONSTRUCTED: u8 = 0b00100000;

    pub const CLASS_UNIVERSAL: u8 = 0b00000000;
    pub const CLASS_APPLICATION: u8 = 0b01000000;
    pub const CLASS_CONTEXTSPECIFIC: u8 = 0b10000000;
    pub const CLASS_PRIVATE: u8 = 0b11000000;

    pub const TYPE_BOOLEAN: u8 = CLASS_UNIVERSAL | PRIMITIVE | 1;
    pub const TYPE_INTEGER: u8 = CLASS_UNIVERSAL | PRIMITIVE | 2;
    pub const TYPE_OCTETSTRING: u8 = CLASS_UNIVERSAL | PRIMITIVE | 4;
    pub const TYPE_NULL: u8 = CLASS_UNIVERSAL | PRIMITIVE | 5;
    pub const TYPE_OBJECTIDENTIFIER: u8 = CLASS_UNIVERSAL | PRIMITIVE | 6;
    pub const TYPE_SEQUENCE: u8 = CLASS_UNIVERSAL | CONSTRUCTED | 16;
    pub const TYPE_SET: u8 = CLASS_UNIVERSAL | CONSTRUCTED | 17;
}

pub mod snmp {
    // #![allow(dead_code, identity_op, eq_op)]

    use super::asn1;
    pub const VERSION_1: i64 = 0;
    pub const VERSION_2: i64 = 1;
    pub const VERSION_3: i64 = 3;

    pub const MSG_GET: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 0;
    pub const MSG_GET_NEXT: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 1;
    pub const MSG_RESPONSE: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 2;
    pub const MSG_SET: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 3;
    pub const MSG_GET_BULK: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 5;
    pub const MSG_INFORM: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 6;
    pub const MSG_TRAP: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 7;
    pub const MSG_REPORT: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 8;

    pub const TYPE_IPADDRESS: u8 = asn1::CLASS_APPLICATION | 0;
    pub const TYPE_COUNTER32: u8 = asn1::CLASS_APPLICATION | 1;
    pub const TYPE_UNSIGNED32: u8 = asn1::CLASS_APPLICATION | 2;
    pub const TYPE_GAUGE32: u8 = TYPE_UNSIGNED32;
    pub const TYPE_TIMETICKS: u8 = asn1::CLASS_APPLICATION | 3;
    pub const TYPE_OPAQUE: u8 = asn1::CLASS_APPLICATION | 4;
    pub const TYPE_COUNTER64: u8 = asn1::CLASS_APPLICATION | 6;

    pub const SNMP_NOSUCHOBJECT: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::PRIMITIVE | 0x0; /* 80=128 */
    pub const SNMP_NOSUCHINSTANCE: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::PRIMITIVE | 0x1; /* 81=129 */
    pub const SNMP_ENDOFMIBVIEW: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::PRIMITIVE | 0x2; /* 82=130 */

    pub const ERRSTATUS_NOERROR: u32 = 0;
    pub const ERRSTATUS_TOOBIG: u32 = 1;
    pub const ERRSTATUS_NOSUCHNAME: u32 = 2;
    pub const ERRSTATUS_BADVALUE: u32 = 3;
    pub const ERRSTATUS_READONLY: u32 = 4;
    pub const ERRSTATUS_GENERR: u32 = 5;
    pub const ERRSTATUS_NOACCESS: u32 = 6;
    pub const ERRSTATUS_WRONGTYPE: u32 = 7;
    pub const ERRSTATUS_WRONGLENGTH: u32 = 8;
    pub const ERRSTATUS_WRONGENCODING: u32 = 9;
    pub const ERRSTATUS_WRONGVALUE: u32 = 10;
    pub const ERRSTATUS_NOCREATION: u32 = 11;
    pub const ERRSTATUS_INCONSISTENTVALUE: u32 = 12;
    pub const ERRSTATUS_RESOURCEUNAVAILABLE: u32 = 13;
    pub const ERRSTATUS_COMMITFAILED: u32 = 14;
    pub const ERRSTATUS_UNDOFAILED: u32 = 15;
    pub const ERRSTATUS_AUTHORIZATIONERROR: u32 = 16;
    pub const ERRSTATUS_NOTWRITABLE: u32 = 17;
    pub const ERRSTATUS_INCONSISTENTNAME: u32 = 18;

    pub const V3_MSG_FLAGS_REPORTABLE: u8 = 0x04;
    pub const V3_MSG_FLAGS_PRIVACY: u8 = 0x02;
    pub const V3_MSG_FLAGS_AUTH: u8 = 0x01;
}

pub mod pdu;

fn decode_i64(i: &[u8]) -> SnmpResult<i64> {
    if i.len() > mem::size_of::<i64>() {
        return Err(SnmpError::AsnIntOverflow);
    }
    let mut bytes = [0u8; 8];
    bytes[(mem::size_of::<i64>() - i.len())..].copy_from_slice(i);

    let mut ret = i64::from_ne_bytes(bytes).to_be();
    {
        //sign extend
        let shift_amount = (mem::size_of::<i64>() - i.len()) * 8;
        ret = (ret << shift_amount) >> shift_amount;
    }
    Ok(ret)
}

pub trait AsOid {
    fn as_oid<'a>(&'a self) -> &'a [u32];
}

impl AsOid for &[u32] {
    fn as_oid<'a>(&'a self) -> &'a [u32] {
        self
    }
}
pub trait AsOidRaw {
    fn as_oid_raw<'a>(&'a self) -> &'a [u8];
}

impl AsOidRaw for &[u8] {
    fn as_oid_raw<'a>(&'a self) -> &'a [u8] {
        self
    }
}

pub trait VarbindOid {
    fn oid<'a>(&'a self) -> &'a [u32];
    fn value<'a>(&'a self) -> Option<&'a Value<'a>>;
}
impl VarbindOid for &[u32] {
    fn oid<'a>(&'a self) -> &'a [u32] {
        self
    }
    fn value<'a>(&'a self) -> Option<&'a Value<'a>> {
        None
    }
}
impl VarbindOid for &&[u32] {
    fn oid<'a>(&'a self) -> &'a [u32] {
        *self
    }
    fn value<'a>(&'a self) -> Option<&'a Value<'a>> {
        None
    }
}
impl VarbindOid for [u32] {
    fn oid<'a>(&'a self) -> &'a [u32] {
        self
    }
    fn value<'a>(&'a self) -> Option<&'a Value<'a>> {
        None
    }
}
impl VarbindOid for Vec<u32> {
    fn oid<'a>(&'a self) -> &'a [u32] {
        &self
    }
    fn value<'a>(&'a self) -> Option<&'a Value<'a>> {
        None
    }
}
impl<const N: usize> VarbindOid for [u32; N] {
    fn oid<'a>(&'a self) -> &'a [u32] {
        self
    }
    fn value<'a>(&'a self) -> Option<&'a Value<'a>> {
        None
    }
}
impl<'v> VarbindOid for (&[u32], Value<'v>) {
    fn oid<'a>(&'a self) -> &'a [u32] {
        self.0
    }
    fn value<'a>(&'a self) -> Option<&'a Value<'a>> {
        Some(&self.1)
    }
}
impl<'v> VarbindOid for &(&[u32], Value<'v>) {
    fn oid<'a>(&'a self) -> &'a [u32] {
        self.0
    }
    fn value<'a>(&'a self) -> Option<&'a Value<'a>> {
        Some(&self.1)
    }
}
impl<'v> VarbindOid for (Vec<u32>, Value<'v>) {
    fn oid<'a>(&'a self) -> &'a [u32] {
        &self.0
    }
    fn value<'a>(&'a self) -> Option<&'a Value<'a>> {
        Some(&self.1)
    }
}
impl<'v> VarbindOid for &(Vec<u32>, Value<'v>) {
    fn oid<'a>(&'a self) -> &'a [u32] {
        &self.0
    }
    fn value<'a>(&'a self) -> Option<&'a Value<'a>> {
        Some(&self.1)
    }
}
/// Wrapper around raw bytes representing an ASN.1 OBJECT IDENTIFIER.
#[derive(PartialEq, Serialize, Deserialize, Clone, Copy)]
pub struct ObjectIdentifier<'a> {
    inner: &'a [u8],
}

impl<'a> AsOidRaw for ObjectIdentifier<'a> {
    fn as_oid_raw<'t>(&'t self) -> &'t [u8] {
        self.inner
    }
}
impl<'a> AsOidRaw for &ObjectIdentifier<'a> {
    fn as_oid_raw<'t>(&'t self) -> &'t [u8] {
        self.inner
    }
}

impl<'a> fmt::Debug for ObjectIdentifier<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.inner).finish()
    }
}

pub type ObjIdBuf = [u32; 128];

impl<'a> fmt::Display for ObjectIdentifier<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = {
            let mut buf: [std::mem::MaybeUninit<u32>; 128] =
                unsafe { std::mem::MaybeUninit::uninit().assume_init() };
            for elem in &mut buf[..] {
                unsafe {
                    std::ptr::write(elem.as_mut_ptr(), 0);
                }
            }
            unsafe { std::mem::transmute::<_, [u32; 128]>(buf) }
        };
        let mut first = true;
        match self.read_name(&mut buf) {
            Ok(name) => {
                for subid in name {
                    if first {
                        first = false;
                        f.write_fmt(format_args!("{}", subid))?;
                    } else {
                        f.write_fmt(format_args!(".{}", subid))?;
                    }
                }
                Ok(())
            }
            Err(err) => f.write_fmt(format_args!("Invalid OID: {:?}", err)),
        }
    }
}

impl<'a> PartialEq<[u32]> for ObjectIdentifier<'a> {
    fn eq(&self, other: &[u32]) -> bool {
        // let mut buf: ObjIdBuf = unsafe { mem::uninitialized() };
        let mut buf = {
            let mut buf: [std::mem::MaybeUninit<u32>; 128] =
                unsafe { std::mem::MaybeUninit::uninit().assume_init() };
            for elem in &mut buf[..] {
                unsafe {
                    std::ptr::write(elem.as_mut_ptr(), 0);
                }
            }
            unsafe { std::mem::transmute::<_, [u32; 128]>(buf) }
        };

        if let Ok(name) = self.read_name(&mut buf) {
            name == other
        } else {
            false
        }
    }
}

impl<'a, 'b> PartialEq<&'b [u32]> for ObjectIdentifier<'a> {
    fn eq(&self, other: &&[u32]) -> bool {
        self == *other
    }
}

impl<'a> ObjectIdentifier<'a> {
    pub fn from_bytes<'src>(bytes: &'src [u8]) -> ObjectIdentifier<'src> {
        ObjectIdentifier { inner: bytes }
    }
    pub fn from_oid(oid: &[u32]) -> Vec<u8> {
        let (head, tail) = oid.split_at(2);
        assert!(head[0] < 3 && head[1] < 40);
        let mut ret = Vec::new();

        // encode the subids in reverse order
        for subid in tail.iter().rev() {
            let mut subid = *subid;
            let mut last_byte = true;
            loop {
                ret.insert(
                    0,
                    if last_byte {
                        last_byte = false;
                        // continue bit is cleared
                        (subid & 0b01111111) as u8
                    } else {
                        // continue bit is set
                        (subid | 0b10000000) as u8
                    },
                );
                subid >>= 7;

                if subid == 0 {
                    break;
                }
            }
        }

        // encode the head last
        ret.insert(0, (head[0] * 40 + head[1]) as u8);
        ret.shrink_to_fit();
        ret
    }
    /*
        pub fn from_str<'b>(s: &'b str) -> ObjectIdentifier<'a> {
           // let mut buf = pdu::Buf::default() ; create this out side the fucntion

            // buf.push_object_identifier(get_oid_array(s).as_slice()) ;

            let mut obuf:[u8;1024] = [0;1024] ;
            let oid_32 = get_oid_array(s) ;
            let input = oid_32.as_slice() ;

            let mut pos = obuf.len() - 1;
            let (head, tail) = input.split_at(2);
            assert!(head[0] < 3 && head[1] < 40);

            // encode the subids in reverse order
            for subid in tail.iter().rev() {
                let mut subid = *subid;
                let mut last_byte = true;
                loop {
                    assert!(pos != 0);
                    if last_byte {
                            // continue bit is cleared
                        obuf[pos] = (subid & 0b01111111) as u8;
                        last_byte = false;
                    } else {
                            // continue bit is set
                        obuf[pos] = (subid | 0b10000000) as u8;
                    }
                    pos -= 1;
                    subid >>= 7;

                    if subid == 0 {
                        break;
                    }
                }
            }

                // encode the head last
            obuf[pos] = (head[0] * 40 + head[1]) as u8;

            ObjectIdentifier::from_bytes( &obuf[obuf.len() - pos..])

        }
    */
    /// Reads out the OBJECT IDENTIFIER sub-IDs as a slice of u32s.
    /// Caller must provide storage for 128 sub-IDs.
    pub fn read_name<'b>(&self, out: &'b mut ObjIdBuf) -> SnmpResult<&'b [u32]> {
        let input = self.inner;
        let output = &mut out[..];
        if input.len() < 2 {
            return Err(SnmpError::AsnInvalidLen);
        }
        let subid1 = (input[0] / 40) as u32;
        let subid2 = (input[0] % 40) as u32;
        output[0] = subid1;
        output[1] = subid2;
        let mut pos = 2;
        let mut cur_oid: u32 = 0;
        let mut is_done = false;
        for b in &input[1..] {
            if pos == output.len() {
                return Err(SnmpError::AsnEof);
            }
            is_done = b & 0b10000000 == 0;
            let val = b & 0b01111111;
            cur_oid = cur_oid.checked_shl(7).ok_or(SnmpError::AsnIntOverflow)?;
            cur_oid |= val as u32;
            if is_done {
                output[pos] = cur_oid;
                pos += 1;
                cur_oid = 0;
            }
        }
        if !is_done {
            Err(SnmpError::AsnParseError)
        } else {
            Ok(&output[..pos])
        }
    }

    pub fn raw(&self) -> &'a [u8] {
        self.inner
    }
}

/// ASN.1/DER decoder iterator.
///
/// Supports:
///
/// - types required by SNMP.
///
/// Does not support:
///
/// - extended tag IDs.
/// - indefinite lengths (disallowed by DER).
/// - INTEGER values not representable by i64.
#[derive(Serialize, Deserialize, Copy)]
pub struct AsnReader<'a> {
    inner: &'a [u8],
    pos: usize,
}

impl<'a> AsRef<[u8]> for AsnReader<'a> {
    fn as_ref(&self) -> &[u8] {
        self.inner
    }
}

impl<'a> Clone for AsnReader<'a> {
    fn clone(&self) -> AsnReader<'a> {
        AsnReader {
            inner: self.inner,
            pos: self.pos,
        }
    }
}

impl<'a> fmt::Debug for AsnReader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<'a> AsnReader<'a> {
    pub fn from_bytes<'arg>(bytes: &'arg [u8]) -> AsnReader<'arg> {
        AsnReader {
            inner: bytes,
            pos: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn bytes_left(&self) -> usize {
        self.inner.len()
    }

    pub fn advance(&mut self, mut offset: usize) {
        if offset < 1 {
            return;
        }
        if offset >= self.inner.len() {
            offset = self.inner.len()
        }
        let (_, remaining) = self.inner.split_at(offset);
        self.pos += offset;
        self.inner = remaining;
    }

    pub fn peek_byte(&self) -> SnmpResult<u8> {
        if self.inner.is_empty() {
            Err(SnmpError::AsnEof)
        } else {
            Ok(self.inner[0])
        }
    }

    pub fn read_byte(&mut self) -> SnmpResult<u8> {
        match self.inner.split_first() {
            Some((head, tail)) => {
                self.inner = tail;
                self.pos += 1;
                Ok(*head)
            }
            _ => Err(SnmpError::AsnEof),
        }
    }

    pub fn read_length(&mut self) -> SnmpResult<usize> {
        if let Some((head, tail)) = self.inner.split_first() {
            let o: usize;
            if head < &128 {
                // short form
                o = *head as usize;
                self.inner = tail;
                self.pos += 1;
                Ok(o)
            } else if head == &0xff {
                Err(SnmpError::AsnInvalidLen) // reserved for future use
            } else {
                // long form
                let length_len = (*head & 0b01111111) as usize;
                if length_len == 0 {
                    // Indefinite length. Not allowed in DER.
                    return Err(SnmpError::AsnInvalidLen);
                }

                let mut bytes = [0u8; USIZE_LEN];
                bytes[(USIZE_LEN - length_len)..].copy_from_slice(&tail[..length_len]);

                o = usize::from_ne_bytes(bytes).to_be();
                self.pos += length_len;
                self.inner = &tail[length_len as usize..];
                Ok(o)
            }
        } else {
            Err(SnmpError::AsnEof)
        }
    }

    pub fn read_i64_type(&mut self, expected_ident: u8) -> SnmpResult<i64> {
        let ident = self.read_byte()?;
        if ident != expected_ident {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (val, remaining) = self.inner.split_at(val_len);
        self.inner = remaining;
        self.pos += val_len;
        decode_i64(val)
    }

    pub fn read_raw(&mut self, expected_ident: u8) -> SnmpResult<&'a [u8]> {
        let ident = self.read_byte()?;
        if ident != expected_ident {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (val, remaining) = self.inner.split_at(val_len);
        self.inner = remaining;
        self.pos += val_len;
        Ok(val)
    }

    pub fn read_constructed<F>(&mut self, expected_ident: u8, f: F) -> SnmpResult<()>
    where
        F: Fn(&mut AsnReader) -> SnmpResult<()>,
    {
        let ident = self.read_byte()?;
        if ident != expected_ident {
            return Err(SnmpError::AsnWrongType);
        }
        let seq_len = self.read_length()?;
        if seq_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (seq_bytes, remaining) = self.inner.split_at(seq_len);
        let mut reader = AsnReader::from_bytes(seq_bytes);
        self.inner = remaining;
        self.pos += seq_len;
        f(&mut reader)
    }

    //
    // ASN
    //

    pub fn read_asn_boolean(&mut self) -> SnmpResult<bool> {
        let ident = self.read_byte()?;
        if ident != asn1::TYPE_NULL {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len != 1 {
            return Err(SnmpError::AsnInvalidLen);
        }
        match self.read_byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SnmpError::AsnParseError), // DER mandates 1/0 for booleans
        }
    }

    pub fn read_asn_integer(&mut self) -> SnmpResult<i64> {
        self.read_i64_type(asn1::TYPE_INTEGER)
    }

    pub fn read_asn_octetstring(&mut self) -> SnmpResult<&'a [u8]> {
        self.read_raw(asn1::TYPE_OCTETSTRING)
    }

    pub fn read_asn_null(&mut self) -> SnmpResult<()> {
        let ident = self.read_byte()?;
        if ident != asn1::TYPE_NULL {
            return Err(SnmpError::AsnWrongType);
        }
        let null_len = self.read_length()?;
        if null_len != 0 {
            Err(SnmpError::AsnInvalidLen)
        } else {
            Ok(())
        }
    }

    pub fn read_asn_objectidentifier(&mut self) -> SnmpResult<ObjectIdentifier<'a>> {
        let ident = self.read_byte()?;
        if ident != asn1::TYPE_OBJECTIDENTIFIER {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (input, remaining) = self.inner.split_at(val_len);
        self.inner = remaining;
        self.pos += val_len;

        Ok(ObjectIdentifier::from_bytes(input))
    }

    pub fn read_asn_sequence<F>(&mut self, f: F) -> SnmpResult<()>
    where
        F: Fn(&mut AsnReader) -> SnmpResult<()>,
    {
        self.read_constructed(asn1::TYPE_SEQUENCE, f)
    }

    // fn read_asn_set<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(asn1::TYPE_SET, f)
    // }

    //
    // SNMP
    //

    pub fn read_snmp_counter32(&mut self) -> SnmpResult<u32> {
        self.read_i64_type(snmp::TYPE_COUNTER32).map(|v| v as u32)
    }

    pub fn read_snmp_unsigned32(&mut self) -> SnmpResult<u32> {
        self.read_i64_type(snmp::TYPE_UNSIGNED32).map(|v| v as u32)
    }

    pub fn read_snmp_timeticks(&mut self) -> SnmpResult<u32> {
        self.read_i64_type(snmp::TYPE_TIMETICKS).map(|v| v as u32)
    }

    pub fn read_snmp_counter64(&mut self) -> SnmpResult<u64> {
        self.read_i64_type(snmp::TYPE_COUNTER64).map(|v| v as u64)
    }

    pub fn read_snmp_opaque(&mut self) -> SnmpResult<&'a [u8]> {
        self.read_raw(snmp::TYPE_OPAQUE)
    }

    pub fn read_snmp_ipaddress(&mut self) -> SnmpResult<[u8; 4]> {
        //let mut ip = [0u8; 4];
        let val = self.read_raw(snmp::TYPE_IPADDRESS)?;
        if val.len() != 4 {
            return Err(SnmpError::AsnInvalidLen);
        }
        //&mut ip[..].copy_from_slice(val);
        //Ok(ip)
        unsafe { Ok(ptr::read(val.as_ptr() as *const _)) }
    }

    // fn read_snmp_get<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_GET, f)
    // }

    // fn read_snmp_getnext<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_GET_NEXT, f)
    // }

    // fn read_snmp_getbulk<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_GET_BULK, f)
    // }

    // fn read_snmp_response<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_RESPONSE, f)
    // }

    // fn read_snmp_inform<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_INFORM, f)
    // }

    // fn read_snmp_report<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_REPORT, f)
    // }

    // fn read_snmp_set<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_SET, f)
    // }

    // fn read_snmp_trap<F>(&mut self, f: F) -> SnmpResult<()>
    //     where F: Fn(&mut AsnReader) -> SnmpResult<()>
    // {
    //     self.read_constructed(snmp::MSG_TRAP, f)
    // }
}

#[derive(Serialize, Deserialize, Copy, Clone)]
pub enum Value<'a> {
    Boolean(bool),
    Null,
    Integer(i64),
    OctetString(&'a [u8]),
    ObjectIdentifier(ObjectIdentifier<'a>),
    Sequence(AsnReader<'a>),
    Set(AsnReader<'a>),
    Constructed(u8, AsnReader<'a>),

    IpAddress([u8; 4]),
    Counter32(u32),
    Unsigned32(u32),
    Timeticks(u32),
    Opaque(&'a [u8]),
    Counter64(u64),

    EndOfMibView,
    NoSuchObject,
    NoSuchInstance,

    SnmpGetRequest(AsnReader<'a>),
    SnmpGetNextRequest(AsnReader<'a>),
    SnmpGetBulkRequest(AsnReader<'a>),
    SnmpResponse(AsnReader<'a>),
    SnmpSetRequest(AsnReader<'a>),
    SnmpInformRequest(AsnReader<'a>),
    SnmpTrap(AsnReader<'a>),
    SnmpReport(AsnReader<'a>),
}
impl<'a> Value<'a> {
    pub fn from_tag_value(tag: u8, value: &'a str) -> Self {
        match tag {
            asn1::TYPE_BOOLEAN => Value::Boolean(value.parse::<bool>().unwrap()),
            asn1::TYPE_NULL => Value::Null,
            asn1::TYPE_INTEGER => Value::Integer(value.parse::<i64>().unwrap()),
            asn1::TYPE_OCTETSTRING => Value::OctetString(value.as_bytes()),
            // asn1::TYPE_OBJECTIDENTIFIER => Value::ObjectIdentifier(ObjectIdentifier::from_str(value)),
            //  asn1::TYPE_SEQUENCE         => self.read_raw(ident).map(|v| Sequence(AsnReader::from_bytes(v))),
            //      asn1::TYPE_SET              => self.read_raw(ident).map(|v| Set(AsnReader::from_bytes(v))),
            snmp::TYPE_IPADDRESS => Value::IpAddress(get_ip_addr(value)),
            snmp::TYPE_COUNTER32 => Value::Counter32(value.parse::<u32>().unwrap()),
            snmp::TYPE_UNSIGNED32 => Value::Unsigned32(value.parse::<u32>().unwrap()),
            snmp::TYPE_TIMETICKS => Value::Timeticks(value.parse::<u32>().unwrap()),
            snmp::TYPE_OPAQUE => Value::Opaque(value.as_bytes()),
            snmp::TYPE_COUNTER64 => Value::Counter64(value.parse::<u64>().unwrap()),
            _ => Value::Integer(value.parse::<i64>().unwrap()),
        }
    }
    pub fn get_string(&self) -> Option<String> {
        match self {
            Value::OctetString(u) => return Some(String::from_utf8_lossy(u).to_string()),
            _ => return Some(format!("{}", self)),
        }
    }
    pub fn get_u64(&self) -> Option<u64> {
        match self {
            Value::Boolean(b) => {
                if *b {
                    return Some(1);
                } else {
                    return Some(0);
                }
            }
            Value::Null => return None,
            Value::Integer(i) => return Some(*i as u64),
            Value::Counter32(u) => return Some(*u as u64),
            Value::Unsigned32(u) => return Some(*u as u64),
            Value::Timeticks(u) => return Some(*u as u64),
            Value::Counter64(u) => return Some(*u as u64),
            _ => return None,
        }
    }
    pub fn get_u32(&self) -> Option<u32> {
        match self {
            Value::Boolean(b) => {
                if *b {
                    return Some(1);
                } else {
                    return Some(0);
                }
            }
            Value::Null => return None,
            Value::Integer(i) => return Some(*i as u32),
            Value::Counter32(u) => return Some(*u as u32),
            Value::Unsigned32(u) => return Some(*u as u32),
            Value::Timeticks(u) => return Some(*u as u32),
            Value::Counter64(u) => return Some(*u as u32),
            _ => return None,
        }
    }
    pub fn get_u8(&self) -> Option<u8> {
        match self {
            Value::Boolean(b) => {
                if *b {
                    return Some(1);
                } else {
                    return Some(0);
                }
            }
            Value::Null => return None,
            Value::Integer(i) => return Some(*i as u8),
            Value::Counter32(u) => return Some(*u as u8),
            Value::Unsigned32(u) => return Some(*u as u8),
            Value::Timeticks(u) => return Some(*u as u8),
            Value::Counter64(u) => return Some(*u as u8),
            _ => return None,
        }
    }
    pub fn get_oid(&self) -> Option<Vec<u32>> {
        match self {
            Value::ObjectIdentifier(u) => {
                let mut oid: ObjIdBuf = [0u32; 128];
                match u.read_name(&mut oid) {
                    Ok(v) => Some(v.to_vec()),
                    Err(_) => None,
                }
            }
            _ => None,
        }
    }
}
impl<'a> fmt::Display for Value<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Value::*;
        match *self {
            Boolean(v) => write!(f, "{}", v),
            Integer(n) => write!(f, "{}", n),
            OctetString(slice) => write!(f, "{}", String::from_utf8_lossy(slice).escape_debug()),
            ObjectIdentifier(ref obj_id) => write!(f, "{}", obj_id),
            Null => write!(f, "NULL"),
            Sequence(ref val) => write!(f, "{:#?}", val),
            Set(ref val) => write!(f, "{:?}", val),
            Constructed(ident, ref val) => write!(f, "{}|{:#?}", ident, val),

            IpAddress(val) => write!(f, "{}.{}.{}.{}", val[0], val[1], val[2], val[3]),
            Counter32(val) => write!(f, "{}", val),
            Unsigned32(val) => write!(f, "{}", val),
            Timeticks(val) => write!(f, "{}", val),
            Opaque(val) => write!(f, "{:?}", val),
            Counter64(val) => write!(f, "{}", val),

            EndOfMibView => write!(f, "END OF MIB VIEW"),
            NoSuchObject => write!(f, "NO SUCH OBJECT"),
            NoSuchInstance => write!(f, "NO SUCH INSTANCE"),

            SnmpGetRequest(ref val) => write!(f, "SNMP GET REQUEST: {:#?}", val),
            SnmpGetNextRequest(ref val) => write!(f, "SNMP GET NEXT REQUEST: {:#?}", val),
            SnmpGetBulkRequest(ref val) => write!(f, "SNMP GET BULK REQUEST: {:#?}", val),
            SnmpResponse(ref val) => write!(f, "SNMP RESPONSE: {:#?}", val),
            SnmpSetRequest(ref val) => write!(f, "SNMP SET REQUEST: {:#?}", val),
            SnmpInformRequest(ref val) => write!(f, "SNMP INFORM REQUEST: {:#?}", val),
            SnmpTrap(ref val) => write!(f, "SNMP TRAP: {:#?}", val),
            SnmpReport(ref val) => write!(f, "SNMP REPORT: {:#?}", val),
        }
    }
}
impl<'a> fmt::Debug for Value<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Value::*;
        match *self {
            Boolean(v) => write!(f, "BOOLEAN: {}", v),
            Integer(n) => write!(f, "INTEGER: {}", n),
            OctetString(slice) => write!(
                f,
                "OCTET STRING: {}",
                String::from_utf8_lossy(slice).escape_debug()
            ),
            ObjectIdentifier(ref obj_id) => write!(f, "OBJECT IDENTIFIER: {}", obj_id),
            Null => write!(f, "NULL"),
            Sequence(ref val) => write!(f, "SEQUENCE: {:#?}", val),
            Set(ref val) => write!(f, "SET: {:?}", val),
            Constructed(ident, ref val) => write!(f, "CONSTRUCTED-{}: {:#?}", ident, val),

            IpAddress(val) => write!(f, "IP ADDRESS: {}.{}.{}.{}", val[0], val[1], val[2], val[3]),
            Counter32(val) => write!(f, "COUNTER32: {}", val),
            Unsigned32(val) => write!(f, "UNSIGNED32: {}", val),
            Timeticks(val) => write!(f, "TIMETICKS: {}", val),
            Opaque(val) => write!(f, "OPAQUE: {:?}", val),
            Counter64(val) => write!(f, "COUNTER64: {}", val),

            EndOfMibView => write!(f, "END OF MIB VIEW"),
            NoSuchObject => write!(f, "NO SUCH OBJECT"),
            NoSuchInstance => write!(f, "NO SUCH INSTANCE"),

            SnmpGetRequest(ref val) => write!(f, "SNMP GET REQUEST: {:#?}", val),
            SnmpGetNextRequest(ref val) => write!(f, "SNMP GET NEXT REQUEST: {:#?}", val),
            SnmpGetBulkRequest(ref val) => write!(f, "SNMP GET BULK REQUEST: {:#?}", val),
            SnmpResponse(ref val) => write!(f, "SNMP RESPONSE: {:#?}", val),
            SnmpSetRequest(ref val) => write!(f, "SNMP SET REQUEST: {:#?}", val),
            SnmpInformRequest(ref val) => write!(f, "SNMP INFORM REQUEST: {:#?}", val),
            SnmpTrap(ref val) => write!(f, "SNMP TRAP: {:#?}", val),
            SnmpReport(ref val) => write!(f, "SNMP REPORT: {:#?}", val),
        }
    }
}

impl<'a> Iterator for AsnReader<'a> {
    type Item = Value<'a>;

    fn next(&mut self) -> Option<Value<'a>> {
        use Value::*;
        if let Ok(ident) = self.peek_byte() {
            let ret: SnmpResult<Value> = match ident {
                asn1::TYPE_BOOLEAN => self.read_asn_boolean().map(Boolean),
                asn1::TYPE_NULL => self.read_asn_null().map(|_| Null),
                asn1::TYPE_INTEGER => self.read_asn_integer().map(Integer),
                asn1::TYPE_OCTETSTRING => self.read_asn_octetstring().map(OctetString),
                asn1::TYPE_OBJECTIDENTIFIER => {
                    self.read_asn_objectidentifier().map(ObjectIdentifier)
                }
                asn1::TYPE_SEQUENCE => self
                    .read_raw(ident)
                    .map(|v| Sequence(AsnReader::from_bytes(v))),
                asn1::TYPE_SET => self.read_raw(ident).map(|v| Set(AsnReader::from_bytes(v))),
                snmp::TYPE_IPADDRESS => self.read_snmp_ipaddress().map(IpAddress),
                snmp::TYPE_COUNTER32 => self.read_snmp_counter32().map(Counter32),
                snmp::TYPE_UNSIGNED32 => self.read_snmp_unsigned32().map(Unsigned32),
                snmp::TYPE_TIMETICKS => self.read_snmp_timeticks().map(Timeticks),
                snmp::TYPE_OPAQUE => self.read_snmp_opaque().map(Opaque),
                snmp::TYPE_COUNTER64 => self.read_snmp_counter64().map(Counter64),
                snmp::MSG_GET => self
                    .read_raw(ident)
                    .map(|v| SnmpGetRequest(AsnReader::from_bytes(v))),
                snmp::MSG_GET_NEXT => self
                    .read_raw(ident)
                    .map(|v| SnmpGetNextRequest(AsnReader::from_bytes(v))),
                snmp::MSG_GET_BULK => self
                    .read_raw(ident)
                    .map(|v| SnmpGetBulkRequest(AsnReader::from_bytes(v))),
                snmp::MSG_RESPONSE => self
                    .read_raw(ident)
                    .map(|v| SnmpResponse(AsnReader::from_bytes(v))),
                snmp::MSG_SET => self
                    .read_raw(ident)
                    .map(|v| SnmpSetRequest(AsnReader::from_bytes(v))),
                snmp::MSG_INFORM => self
                    .read_raw(ident)
                    .map(|v| SnmpInformRequest(AsnReader::from_bytes(v))),
                snmp::MSG_TRAP => self
                    .read_raw(ident)
                    .map(|v| SnmpTrap(AsnReader::from_bytes(v))),
                snmp::MSG_REPORT => self
                    .read_raw(ident)
                    .map(|v| SnmpReport(AsnReader::from_bytes(v))),
                ident if ident & asn1::CONSTRUCTED == asn1::CONSTRUCTED => self
                    .read_raw(ident)
                    .map(|v| Constructed(ident, AsnReader::from_bytes(v))),
                _ => Err(SnmpError::AsnUnsupportedType),
            };
            ret.ok()
        } else {
            None
        }
    }
}

#[cfg(feature = "sync")]
pub mod sync;

#[derive(Debug)]
pub struct SnmpPdu<'a> {
    pub version: i64,
    pub community: &'a [u8],
    pub message_type: SnmpMessageType,
    pub req_id: i32,
    pub error_status: u32,
    pub error_index: u32,
    pub varbinds: Varbinds<'a>,
    #[cfg(feature = "v3")]
    pub v3_msg_id: i32,
}

impl<'a> SnmpPdu<'a> {
    pub(crate) fn from_bytes_inner<'t>(
        mut rdr: AsnReader<'t>,
        version: i64,
    ) -> SnmpResult<SnmpPdu<'t>> {
        let community = rdr.read_asn_octetstring()?;
        let ident = rdr.peek_byte()?;
        let message_type = SnmpMessageType::from_ident(ident)?;

        let mut response_pdu = AsnReader::from_bytes(rdr.read_raw(ident)?);

        let req_id = response_pdu.read_asn_integer()?;
        if req_id < i32::min_value() as i64 || req_id > i32::max_value() as i64 {
            return Err(SnmpError::ValueOutOfRange);
        }

        let error_status = response_pdu.read_asn_integer()?;
        if error_status < 0 || error_status > i32::max_value() as i64 {
            return Err(SnmpError::ValueOutOfRange);
        }

        let error_index = response_pdu.read_asn_integer()?;
        if error_index < 0 || error_index > i32::max_value() as i64 {
            return Err(SnmpError::ValueOutOfRange);
        }

        let varbind_bytes = response_pdu.read_raw(asn1::TYPE_SEQUENCE)?;
        let varbinds = Varbinds::from_bytes(varbind_bytes);

        Ok(SnmpPdu {
            version,
            community,
            message_type,
            req_id: req_id as i32,
            error_status: error_status as u32,
            error_index: error_index as u32,
            varbinds,
            #[cfg(feature = "v3")]
            v3_msg_id: 0,
        })
    }

    pub fn from_bytes(bytes: &'a [u8]) -> SnmpResult<SnmpPdu<'a>> {
        let seq = AsnReader::from_bytes(bytes).read_raw(asn1::TYPE_SEQUENCE)?;
        let mut rdr = AsnReader::from_bytes(seq);
        let version = rdr.read_asn_integer()?;
        if version > 1 || version < 0 {
            return Err(SnmpError::UnsupportedVersion);
        }
        Self::from_bytes_inner(rdr, version)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum SnmpMessageType {
    GetRequest,
    GetNextRequest,
    GetBulkRequest,
    Response,
    SetRequest,
    InformRequest,
    Trap,
    Report,
}

impl SnmpMessageType {
    pub fn from_ident(ident: u8) -> SnmpResult<SnmpMessageType> {
        use SnmpMessageType::*;
        Ok(match ident {
            snmp::MSG_GET => GetRequest,
            snmp::MSG_GET_NEXT => GetNextRequest,
            snmp::MSG_GET_BULK => GetBulkRequest,
            snmp::MSG_RESPONSE => Response,
            snmp::MSG_SET => SetRequest,
            snmp::MSG_INFORM => InformRequest,
            snmp::MSG_TRAP => Trap,
            snmp::MSG_REPORT => Report,
            _ => return Err(SnmpError::AsnWrongType),
        })
    }
}

#[derive(Clone)]
pub struct Varbinds<'a> {
    pub(crate) inner: AsnReader<'a>,
}

impl<'a> fmt::Debug for Varbinds<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // f.debug_list().entries(self.clone()).finish()
        let mut ds = f.debug_struct("Varbinds");
        for (name, val) in self.clone() {
            ds.field(&format!("{}", name), &format!("{:?}", val));
        }
        ds.finish()
    }
}

impl<'a> Varbinds<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Varbinds<'a> {
        Varbinds {
            inner: AsnReader::from_bytes(bytes),
        }
    }
    pub fn pos(&self) -> usize {
        self.inner.pos()
    }

    pub fn advance(&mut self, offset: usize) {
        self.inner.advance(offset)
    }
}

impl<'a> AsRef<[u8]> for Varbinds<'a> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl<'a> Iterator for Varbinds<'a> {
    type Item = (ObjectIdentifier<'a>, Value<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(seq) = self.inner.read_raw(asn1::TYPE_SEQUENCE) {
            let mut pair = AsnReader::from_bytes(seq);
            if let (Ok(name), Some(value)) = (pair.read_asn_objectidentifier(), pair.next()) {
                return Some((name, value));
            }
        }
        None
    }
}

pub fn get_oid_array(oid: &str) -> Vec<u32> {
    // to comvert to a slice add as_slice()
    oid.split('.')
        .collect::<Vec<&str>>()
        .iter()
        .map(|x| x.parse::<u32>().unwrap_or(0))
        .collect::<Vec<u32>>()
}
pub fn get_ip_addr(oid: &str) -> [u8; 4] {
    // to comvert to a slice add as_slice()
    let vec = oid
        .split('.')
        .collect::<Vec<&str>>()
        .iter()
        .map(|x| x.parse::<u8>().unwrap_or(0))
        .collect::<Vec<u8>>();
    let mut ret_data = [0; 4];
    ret_data.copy_from_slice(vec.as_slice());
    ret_data
}

pub fn get_str_from_oid_arr(arr: &[u32]) -> String {
    arr.iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(".")
}

pub fn read_oid(oid: &ObjectIdentifier) -> String {
    // let mut obuf: ObjIdBuf = unsafe {  mem::uninitialized() };
    let mut obuf = {
        let mut obuf: [std::mem::MaybeUninit<u32>; 128] =
            unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        for elem in &mut obuf[..] {
            unsafe {
                std::ptr::write(elem.as_mut_ptr(), 0);
            }
        }
        unsafe { std::mem::transmute::<_, [u32; 128]>(obuf) }
    };
    let req_oid = oid.read_name(&mut obuf).unwrap();
    get_str_from_oid_arr(req_oid)
}
pub fn get_the_tag_value(value: &Value) -> (u8, String) {
    match value {
        Value::Boolean(v) => (asn1::TYPE_BOOLEAN, v.to_string()),
        Value::Integer(n) => (asn1::TYPE_INTEGER, n.to_string()),
        Value::OctetString(slice) => (
            asn1::TYPE_OCTETSTRING,
            String::from_utf8_lossy(slice).to_string(),
        ),
        Value::ObjectIdentifier(ref obj_id) => (asn1::TYPE_OBJECTIDENTIFIER, read_oid(obj_id)),
        Value::Null => (asn1::TYPE_NULL, "NULL".to_string()),
        Value::IpAddress(val) => (
            snmp::TYPE_IPADDRESS,
            format!("{}.{}.{}.{}", val[0], val[1], val[2], val[3]),
        ),
        Value::Counter32(n) => (snmp::TYPE_COUNTER32, n.to_string()),
        Value::Unsigned32(n) => (snmp::TYPE_UNSIGNED32, n.to_string()),
        Value::Timeticks(n) => (snmp::TYPE_TIMETICKS, n.to_string()),
        Value::Opaque(slice) => (
            snmp::TYPE_OPAQUE,
            String::from_utf8_lossy(slice).to_string(),
        ),
        Value::Counter64(n) => (snmp::TYPE_COUNTER64, n.to_string()),
        _ => (asn1::TYPE_INTEGER, "unknown".to_string()),
    }
}
pub fn get_the_tag(value: &Value) -> u8 {
    match value {
        Value::Boolean(_v) => asn1::TYPE_BOOLEAN,
        Value::Integer(_n) => asn1::TYPE_INTEGER,
        Value::OctetString(_slice) => asn1::TYPE_OCTETSTRING,
        Value::ObjectIdentifier(ref _obj_id) => asn1::TYPE_OBJECTIDENTIFIER,
        Value::Null => asn1::TYPE_NULL,
        Value::IpAddress(_val) => snmp::TYPE_IPADDRESS,
        Value::Counter32(_n) => snmp::TYPE_COUNTER32,
        Value::Unsigned32(_n) => snmp::TYPE_UNSIGNED32,
        Value::Timeticks(_n) => snmp::TYPE_TIMETICKS,
        Value::Opaque(_slice) => snmp::TYPE_OPAQUE,
        Value::Counter64(_n) => snmp::TYPE_COUNTER64,
        _ => asn1::TYPE_INTEGER,
    }
}
/*
pub fn get_the_value_from_tv(tv:(u8,&str)) -> Value {
   let (tag, value ) = tv ;
   match tag {
    asn1::TYPE_BOOLEAN => Value::Boolean(value.parse::<bool>().unwrap()),
    asn1::TYPE_INTEGER => Value::Integer(value.parse::<i64>().unwrap()),
    asn1::TYPE_OCTETSTRING => Value::OctetString(value.as_bytes()),
    asn1::TYPE_OBJECTIDENTIFIER => Value::ObjectIdentifier(value.as_bytes()),
   }
}
*/
fn push_char(v: &mut Vec<u8>, c: char) {
    let mut u = c as u32;
    if c.len_utf8() == 1 {
        v.push(u as u8);
    } else {
        for _ in 0..c.len_utf8() {
            v.push((u & 0xff) as u8);
            u = u >> 8;
        }
    }
}

pub(crate) fn unescape_ascii(s: &str) -> Vec<u8> {
    let mut ret = Vec::new();
    let mut mode = 0;
    let mut accum = 0u32;
    'st: for c in s.chars() {
        'cnt: loop {
            match mode {
                0 => match c {
                    '\\' => mode = 1,
                    _ => {
                        push_char(&mut ret, c);
                    }
                },
                1 => {
                    mode = 0;
                    match c {
                        '\\' => ret.push('\\' as u8),
                        't' => ret.push(9),
                        'r' => ret.push(13),
                        'n' => ret.push(10),
                        '0' => {
                            mode = 2;
                            accum = 0;
                        } //octal
                        'x' | 'X' => {
                            mode = 3;
                            accum = 0;
                        } //hexadecimal
                        _ => {
                            ret.push('\\' as u8);
                            push_char(&mut ret, c);
                        }
                    }
                }
                2 => match c {
                    '0'..='7' => {
                        let accumn = accum * 8 + ((c as u32) - 48);
                        if accumn > 255 {
                            ret.push(accum as u8);
                            push_char(&mut ret, c);
                            mode = 0;
                        } else {
                            accum = accumn;
                        }
                        continue 'st;
                    }
                    _ => {
                        ret.push(accum as u8);
                        mode = 0;
                        continue 'cnt;
                    }
                },
                3 => match c {
                    '0'..='9' | 'a'..='f' | 'A'..='F' => {
                        let accumn = accum * 16 + c.to_digit(16).unwrap();
                        if accumn > 255 {
                            ret.push(accum as u8);
                            mode = 0;
                            continue 'cnt;
                        } else {
                            accum = accumn;
                        }
                        continue 'st;
                    }
                    _ => {
                        ret.push(accum as u8);
                        mode = 0;
                        continue 'cnt;
                    }
                },
                _ => {
                    mode = 0;
                    continue 'cnt;
                }
            }
            break;
        }
    }
    ret
}
