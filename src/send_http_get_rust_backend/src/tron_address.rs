use std::fmt;
use std::fmt::Display;
use std::str::FromStr;
use hex::FromHex;
use sha3::{Digest, Keccak256};
use sha2::Sha256;
use base58::{FromBase58, ToBase58};

/// The mainnet uses 0x41('A') as address type prefix.
const ADDRESS_TYPE_PREFIX: u8 = 0x41;

/// Address of Tron, saved in 21-byte format.
#[derive(PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
pub struct TronAddress([u8; 21]);

// Name => Address
const WELLKNOWN_ADDRESS: &[(&str, &str)] = &[
    ("410000000000000000000000000000000000000000", "0"),
    ("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "USDT"),
    ("TWVVcRqRmpyAi9dASvTXrqnS7FrwvDezMn", "OKS"),
    ("TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE", "S-USDT-TRX"),
    ("TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR", "WTRX"),
    ("TKfjV9RNKJJCqPvBtK8L7Knykh7DNWvnYt", "WBTT"),
    ("TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9", "BTC"),
    ("TXpw8XeWYeTUd4quDskoUqeQPowRh4jY65", "WBTC"),
    ("THb4CqiFdwNHsWsQCs4JhzwjMWys4aqCbF", "ETH"),
    ("TVrZ3PjjFGbnp44p6SGASAKrJWAUjCHmCA", "JustSwap"),
    ("TQEuSEVRk1GtfExm5q9T8a1w84GvgQJ13V", "ShieldedUSDT"),
];

impl TronAddress {
    /// Address of a public key.
    pub fn from_public(public: [u8; 64]) -> TronAddress {
        let mut hasher = Keccak256::new();
        hasher.update(public.as_ref());
        let keccak256_hash = hasher.finalize();

        let mut raw = [ADDRESS_TYPE_PREFIX; 21];
        raw[1..21].copy_from_slice(&keccak256_hash[keccak256_hash.len() - 20..]);

        TronAddress(raw)
    }

    /*
    /// Address of a private key.
    pub fn from_private(private: &Private) -> Address {
        Address::from_public(&Public::from_private(private).expect("public from private; qed"))
    }
     */

    /// As raw 21-byte address.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// As 20-byte address that compatiable with Ethereum.
    pub fn as_tvm_bytes(&self) -> &[u8] {
        &self.0[1..]
    }

    /// Address from 20-byte address that compatiable with Ethereum.
    pub fn from_tvm_bytes(raw: &[u8]) -> Self {
        assert!(raw.len() == 20);

        let mut inner = [ADDRESS_TYPE_PREFIX; 21];
        inner[1..21].copy_from_slice(raw);
        TronAddress(inner)
    }

    /// Address rom raw 21-byte.
    pub fn from_bytes(raw: &[u8]) -> &TronAddress {
        assert!(raw.len() == 21);

        unsafe { std::mem::transmute(&raw[0]) }
    }

    /// To hex address, i.e. 41-address.
    pub fn to_hex_address(&self) -> String {
        hex::encode(self.0)
    }

    /// ETH Address.
    /// Ref: EIP-55 Mixed-case checksum address encoding
    pub fn to_eth_address(&self) -> String {
        let mut addr = format!("0x{}", hex::encode(self.as_tvm_bytes()));
        eip55_checksum(unsafe { &mut addr.as_bytes_mut()[2..] });
        addr
    }

    /// Is this a well-known address.
    pub fn to_well_known_name(&self) -> Option<String> {
        WELLKNOWN_ADDRESS
            .iter()
            .find(|(addr, _name)| addr == &self.to_string())
            .map(|(_, name)| format!("/{}", name))
    }
}

impl Default for TronAddress {
    fn default() -> Self {
        TronAddress([0x41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }
}

impl fmt::Display for TronAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        b58encode_check(&self.0).fmt(f)
    }
}

impl ::std::fmt::Debug for TronAddress {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        f.debug_tuple("Address").field(&self.to_string()).finish()
    }
}

impl TryFrom<&[u8]> for TronAddress {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 21 {
            Err(Error::InvalidAddress)
        } else {
            let mut raw = [0u8; 21];
            raw[..21].copy_from_slice(value);
            Ok(TronAddress(raw))
        }
    }
}

impl TryFrom<Vec<u8>> for TronAddress {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&value[..])
    }
}

impl TryFrom<&Vec<u8>> for TronAddress {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&value[..])
    }
}

impl TryFrom<&str> for TronAddress {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        TronAddress::from_str(value)
    }
}

impl FromHex for TronAddress {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        TronAddress::try_from(hex.as_ref())
    }
}

impl FromStr for TronAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error>
        where
            Self: Sized,
    {
        if s.len() == 34 {
            b58decode_check(s).and_then(TronAddress::try_from)
        } else if s.len() == 42 && s[..2] == hex::encode(&[ADDRESS_TYPE_PREFIX]) {
            Vec::from_hex(s)
                .map_err(|_| Error::InvalidAddress)
                .and_then(TronAddress::try_from)
        } else if s.len() == 44 && (s.starts_with("0x") || s.starts_with("0X")) {
            Vec::from_hex(&s.as_bytes()[2..])
                .map_err(|_| Error::InvalidAddress)
                .and_then(TronAddress::try_from)
        } else if s == "_" || s == "0x0" || s == "/0" {
            "410000000000000000000000000000000000000000".parse()
        } else if s.starts_with("/") {
            // look up from well-known addresses
            WELLKNOWN_ADDRESS
                .iter()
                .find(|(_addr, name)| &&s[1..] == name)
                .ok_or_else(|| Error::InvalidAddress)?
                .0
                .parse()
        } else {
            eprintln!("len={} prefix={:x}", s.len(), s.as_bytes()[0]);
            Err(Error::InvalidAddress)
        }
    }
}

// NOTE: AsRef<[u8]> implies ToHex
impl AsRef<[u8]> for TronAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Base58check encode.
pub fn b58encode_check<T: AsRef<[u8]>>(raw: T) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_ref());
    let digest1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&digest1);
    let digest = hasher.finalize();

    let mut raw = raw.as_ref().to_owned();
    raw.extend(&digest[..4]);
    raw.to_base58()
}

/// Base58check decode.
pub fn b58decode_check(s: &str) -> Result<Vec<u8>, Error> {
    let mut result = s.from_base58().map_err(|_| Error::InvalidAddress)?;

    let check = result.split_off(result.len() - 4);

    let mut hasher = Sha256::new();
    hasher.update(&result);
    let digest1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&digest1);
    let digest = hasher.finalize();

    if check != &digest[..4] {
        Err(Error::InvalidChecksum)
    } else {
        Ok(result)
    }
}

fn eip55_checksum(hex_address: &mut [u8]) {
    let mut hasher = Keccak256::new();
    hasher.update(&hex_address);
    let hashed_address = hex::encode(hasher.finalize());

    hex_address
        .iter_mut()
        .zip(hashed_address.as_bytes().iter())
        .for_each(|(c, &h)| match *c {
            b'a'..=b'f' if h > b'7' => {
                *c = c.to_ascii_uppercase();
            }
            _ => (),
        });
}



/// Key Errors.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Digest data format error.
    InvalidMessage,
    /// Signature data format error.
    InvalidSignature,
    /// Invalid checksum of base58check.
    InvalidChecksum,
    /// Invalid address format.
    InvalidAddress,
    /// Unable to generate a key pair.
    FailedKeyGeneration,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            Error::InvalidMessage => "Invalid Message",
            Error::InvalidSignature => "Invalid Signature",
            Error::InvalidChecksum => "Invalid Checksum",
            Error::InvalidAddress => "Invalid Address",
            Error::FailedKeyGeneration => "Key generation failed",
        };

        msg.fmt(f)
    }
}