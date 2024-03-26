mod tron_address;

use std::any::Any;
//1. IMPORT MANAGEMENT CANISTER
//This includes all methods and types needed
use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse, TransformArgs,
    TransformContext, TransformFunc,
};

use ic_cdk_macros::{self, query, update};

use ic_stable_structures::{StableBTreeMap, DefaultMemoryImpl};
use std::cell::RefCell;
use std::ops::Add;
use candid::{CandidType, Encode, Nat, Principal};
use ic_cdk::caller;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::ptr;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use crate::tron_address::TronAddress;


type CanisterId = Principal;

//Stable memory wallets
thread_local! {
    static WALLETS_COUNTER: RefCell<u32> = RefCell::new(0);
    static WALLETS: RefCell<StableBTreeMap<([u8; 65], u32), (([u8; 65], u32), Principal), DefaultMemoryImpl>> =
    RefCell::new(StableBTreeMap::init(DefaultMemoryImpl::default()));
}

#[derive(CandidType, Serialize, Debug)]
struct ECDSAPublicKey {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct ECDSAPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug)]
struct SignWithECDSA {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct SignWithECDSAReply {
    pub signature: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug, Clone)]
struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

#[derive(CandidType, Serialize, Debug, Clone)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

#[derive(CandidType, Deserialize, Debug, Clone, Copy)]
#[repr(i32)]
pub enum WalletSymbol {
    #[serde(rename = "TRON")]
    TRON,
    SOL,
}


/// A helper function to access the anchor-based index.
fn with_wallets_mut<R>(f: impl FnOnce(&mut StableBTreeMap<([u8; 65], u32), (([u8; 65], u32), Principal), DefaultMemoryImpl>) -> R) -> R {
    WALLETS.with(|cell| f(&mut cell.borrow_mut()))
}
fn get_and_increment_counter() -> u32 {
    WALLETS_COUNTER.with(|cell| {
        let c = cell.borrow().clone();
        *cell.borrow_mut() += 1;
        c
    })
}

//create_wallet
#[ic_cdk::update]
async fn new_wallet(symbol: WalletSymbol) -> Result<String, String> {
    let caller = caller();
    //TODO: guard

    let wallet_symbol_id = symbol as u32;
    ic_cdk::println!("symbol {:?}", wallet_symbol_id);
    let counter = get_and_increment_counter();
    ic_cdk::println!("counter {:?}", counter);

    let mut counter_vec = Vec::new();
    unsafe {
        let counter_slice: [u8; 4] = std::mem::transmute(counter);
        counter_vec.extend_from_slice(&counter_slice)
    }
    ic_cdk::println!("counter vector {:?}", counter_vec);

    let request = ECDSAPublicKey {
        canister_id: None,
        derivation_path: vec![caller.as_slice().to_vec(), counter_vec],
        key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id()
    };

    let (res,): (ECDSAPublicKeyReply,) =
        ic_cdk::call(mgmt_canister_id(), "ecdsa_public_key", (request,))
            .await
            .map_err(|e| format!("ecdsa_public_key failed {}", e.1))?;

    let full_key: [u8; 65] = <[u8; 65]>::try_from(k256::PublicKey::from_sec1_bytes(res.public_key.as_slice())
        .expect("failed to deserialize sec1 encoding into public key")
        .as_affine().to_encoded_point(false).as_bytes()).unwrap();

    let mut public_key_array: [u8; 64] = [0; 64];
    public_key_array.copy_from_slice(&full_key[1..]);

    ic_cdk::println!("public key uncompressed: {:02x?} of size {:?}", full_key, full_key.len());
    ic_cdk::println!("public key sliced: {:02x?} of size {:?}", public_key_array, public_key_array.len());

    //TODO: switch on wallet_symbol_id
    let tron_address = TronAddress::from_public(public_key_array);

    ic_cdk::println!("before panic: {:?}", tron_address.as_bytes());
    let mut abstract_address: [u8; 65] = [0; 65];
    abstract_address[0..21].copy_from_slice(tron_address.as_bytes());

    ic_cdk::println!("public key: {:02x?} of size {:?}", res.public_key.as_slice(), res.public_key.len());
    ic_cdk::println!("tron address: {:?}", tron_address);
    ic_cdk::println!("tron address bytes: {:?}", abstract_address);

    with_wallets_mut(|wallets| {
        wallets.insert((abstract_address, wallet_symbol_id), ((full_key, counter), caller))
    });

    Ok("ok".to_string())
}

#[ic_cdk::query]
fn list_wallets(symbol: WalletSymbol) -> Vec<String> {
    let caller = caller();
    //TODO: guard
    let wallet_symbol_id = symbol as u32;

    with_wallets_mut(|wallets| {
        wallets.iter().filter_map(|w| {
            if w.0.1 == wallet_symbol_id && w.1.1 == caller {
                match symbol {
                    WalletSymbol::TRON => {
                        Some(TronAddress::from_bytes(&w.0.0[0..21]).to_string())
                    }
                    _ => None
                }
            } else {None}
        }).collect()
    })
}



//Update method using the HTTPS outcalls feature
#[ic_cdk::update]
async fn get_icp_usd_exchange() -> String {
    //2. SETUP ARGUMENTS FOR HTTP GET request

    // 2.1 Setup the URL and its query parameters
    type Timestamp = u64;
    let start_timestamp: Timestamp = 1682978460; //May 1, 2023 22:01:00 GMT
    let seconds_of_time: u64 = 60; //start with 60 seconds
    let host = "localhost";
    let url = format!(
        //"https://{}/products/ICP-USD/candles?start={}&end={}&granularity={}",
        "https://{}/check",
        host
    );

    // 2.2 prepare headers for the system http_request call
    //Note that `HttpHeader` is declared in line 4
    let request_headers = vec![
        HttpHeader {
            name: "Host".to_string(),
            value: format!("{host}:443"),
        },
        HttpHeader {
            name: "User-Agent".to_string(),
            value: "exchange_rate_canister".to_string(),
        },
    ];

    //note "CanisterHttpRequestArgument" and "HttpMethod" are declared in line 4
    let request = CanisterHttpRequestArgument {
        url: url.to_string(),
        method: HttpMethod::GET,
        body: None,               //optional for request
        max_response_bytes: None, //optional for request
        transform: Some(TransformContext {
            // The "method" parameter needs to the same name as the function name of your transform function
            function: TransformFunc(candid::Func {
                principal: ic_cdk::api::id(),
                method: "transform".to_string(),
            }),
            // The "TransformContext" function does need a context parameter, it can be empty
            context: vec![],
        }),
        headers: request_headers,
    };

    //3. MAKE HTTPS REQUEST AND WAIT FOR RESPONSE

    //Note: in Rust, `http_request()` needs to pass cycles if you are using ic_cdk: ^0.9.0
    let cycles = 230_949_972_000;

    match http_request(request, cycles).await {
        //4. DECODE AND RETURN THE RESPONSE

        //See:https://docs.rs/ic-cdk/latest/ic_cdk/api/management_canister/http_request/struct.HttpResponse.html
        Ok((response,)) => {
            //if successful, `HttpResponse` has this structure:
            // pub struct HttpResponse {
            //     pub status: Nat,
            //     pub headers: Vec<HttpHeader>,
            //     pub body: Vec<u8>,
            // }

            //You need to decode that Vec<u8> that is the body into readable text.
            //To do this:
            //  1. Call `String::from_utf8()` on response.body
            //  3. You use a switch to explicitly call out both cases of decoding the Blob into ?Text

            //The API response will looks like this:

            // ("[[1682978460,5.714,5.718,5.714,5.714,243.5678]]")

            //Which can be formatted as this
            //  [
            //     [
            //         1682978460, <-- start/timestamp
            //         5.714, <-- low
            //         5.718, <-- high
            //         5.714, <-- open
            //         5.714, <-- close
            //         243.5678 <-- volume
            //     ],
            //  ]

            //Return the body as a string and end the method
            String::from_utf8(response.body).expect("Transformed response is not UTF-8 encoded.")
        }
        Err((r, m)) => {
            let message =
                format!("The http_request resulted into error. RejectionCode: {r:?}, Error: {m}");

            //Return the error as a string and end the method
            message
        }
    }
}

// Strips all data that is not needed from the original response.
#[ic_cdk::query]
fn transform(raw: TransformArgs) -> HttpResponse {
    let headers = vec![
        HttpHeader {
            name: "Content-Security-Policy".to_string(),
            value: "default-src 'self'".to_string(),
        },
        HttpHeader {
            name: "Referrer-Policy".to_string(),
            value: "strict-origin".to_string(),
        },
        HttpHeader {
            name: "Permissions-Policy".to_string(),
            value: "geolocation=(self)".to_string(),
        },
        HttpHeader {
            name: "Strict-Transport-Security".to_string(),
            value: "max-age=63072000".to_string(),
        },
        HttpHeader {
            name: "X-Frame-Options".to_string(),
            value: "DENY".to_string(),
        },
        HttpHeader {
            name: "X-Content-Type-Options".to_string(),
            value: "nosniff".to_string(),
        },
    ];

    let mut res = HttpResponse {
        status: raw.response.status.clone(),
        body: raw.response.body.clone(),
        headers,
    };

    if res.status == 200u64 {
        res.body = raw.response.body;
    } else {
        ic_cdk::api::print(format!("Received an error from coinbase: err = {:?}", raw));
    }
    res
}



fn mgmt_canister_id() -> CanisterId {
    CanisterId::from_str(&"aaaaa-aa").unwrap()
}

enum EcdsaKeyIds {
    #[allow(unused)]
    TestKeyLocalDevelopment,
    #[allow(unused)]
    TestKey1,
    #[allow(unused)]
    ProductionKey1,
}

impl EcdsaKeyIds {
    fn to_key_id(&self) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: match self {
                Self::TestKeyLocalDevelopment => "dfx_test_key",
                Self::TestKey1 => "test_key_1",
                Self::ProductionKey1 => "key_1",
            }
                .to_string(),
        }
    }
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of k256) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// we only use the k256 crate for verifying secp256k1 signatures, and such
// signature verification does not require any randomness.
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}