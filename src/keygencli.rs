

#![feature(map_first_last)]
//use afwalletclient::*;
#![recursion_limit = "128"]
#![feature(proc_macro_hygiene)]
#![feature(decl_macro)]
#[macro_use]
extern crate rocket;
extern crate config;
extern crate curv;
extern crate multi_party_ecdsa;
extern crate rocket_contrib;
extern crate uuid;
extern crate zk_paillier;
#[macro_use]
extern crate failure;

#[macro_use]
extern crate error_chain;

extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate log;

#[cfg(test)]
//#[macro_use]
extern crate time_test;
extern crate floating_duration;

extern crate crypto;
extern crate hex;

#[macro_use]
extern crate serde_derive;
pub mod ecdsa;
pub mod util;
pub mod sdk;

use std::os::raw::{c_int, c_void};

extern "C" fn callback(i: c_int, _c_user_data: *mut c_void) {
    println!("Round{}", i);
}

fn main() {
    
    let null: *mut c_void = std::ptr::null_mut();

    let nc = sdk::network::NetworkClient::new("{\"server\": \"http://127.0.0.1:8000\"}");
    let result = sdk::keygen::keygen(&nc, callback, null).expect("Failed to generate key pair");

    let keygen_result = serde_json::to_string(&result).unwrap();
    println!("{}", keygen_result);
}
