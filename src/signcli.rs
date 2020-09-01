

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
extern crate rocksdb;
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
#[macro_use]
extern crate time_test;
extern crate floating_duration;

extern crate crypto;
extern crate jsonwebtoken as jwt;
extern crate rusoto_dynamodb;
extern crate hex;

#[macro_use]
extern crate serde_derive;
pub mod ecdsa;
pub mod wallet;
pub mod util;
pub mod web;
pub mod sdk;

use std::os::raw::{c_int, c_void};

extern "C" fn callback(i: c_int, _c_user_data: *mut c_void) {
    println!("Round{}", i);
}

fn main() {
    
    let null: *mut c_void = std::ptr::null_mut();

    let nc = sdk::network::NetworkClient::new("{\"server\": \"http://127.0.0.1:8000\"}");
    let wallet = String::from("[\"b005db4f-c3cf-4f58-88fa-eceefcf30e76\",{\"u_i\":\"5af9be91745cb1faf114a3bfc93475a138481969749f794e4cbff3c3538aec06\",\"y_i\":{\"x\":\"1e199b3ffba956e0c1d612389626c405c9fcbb0589e8d4af277257bad6f43992\",\"y\":\"657c698c5fd5d4657cd71889786149d8622cce4b01706fd1eb24405430a2cb7c\"},\"dk\":{\"p\":\"102436931575215908658203758544580405192187269228355640162861178028649765883151729595079365648148253732035589929082645712436864984305260138327649770095562852806624345825579767655523755473074982051956259274594251398208240029887916522019272966806888071508555391049261047860399587853726252959533977359454072597359\",\"q\":\"137719376209865103603864297088871968058661589559917292221397605997582203197267480731806265637194330308669145126776956734686086512441372194357209105501308719587113339747646387473406248721754468562324898583325912377456619072070474800982530430846368761312643240010577103094850765256459716856586177508246563282059\"},\"ek\":{\"n\":\"14107550317391369263575463507015434182923004620199500800448925994447321135196177984568045819936245893125423502854322785339519193156963117749573003448024256131633277379894492731953435879913802019305654271839378741523056036615760644794537058994163510522644745328335949388556091621824287287832718208894982246355699621216515700145199754292162726238226880977123697951320440492310065321112128693483342525896671001734837709922544910385719227735963737912270114963280659165453684525783897524791334895017889996564378823428084870601384092515056078959343761987414261335372085364008224029567030922285601471748180533450889855482181\"},\"party_index\":2},{\"y\":{\"x\":\"3fb18e0171552e90c2f375a72ba0675ef550549c9c94b7c8a4d13468f980dd3c\",\"y\":\"6b96b3354277eeac5b7074a4fca720a2b6350733177c825368a6ecd8f12beaea\"},\"x_i\":\"4de56cca5b6c85533a538c3868e0dd67b7fb305735d6b759458b8a69fc3f9065\"},2,[{\"parameters\":{\"threshold\":1,\"share_count\":2},\"commitments\":[{\"x\":\"87f754025d1b84f24f3b7af040e5e89482239e9cbc8c0d35e22fe64acbeb8908\",\"y\":\"ffa2bf312332a132f5e6b0b4093a7b2246ce11d147b2b2010e9e8d336bed7ad9\"},{\"x\":\"f0429553a8e948bc2f37aeb34a9332e3564a000a51ac39c4d9dd463b4eb4018a\",\"y\":\"76e79dc34017736bf48349641a13b0abf5f5a69b768320d9f0fa1230b53313ad\"}]},{\"parameters\":{\"threshold\":1,\"share_count\":2},\"commitments\":[{\"x\":\"1e199b3ffba956e0c1d612389626c405c9fcbb0589e8d4af277257bad6f43992\",\"y\":\"657c698c5fd5d4657cd71889786149d8622cce4b01706fd1eb24405430a2cb7c\"},{\"x\":\"e3cde950682eca66246bb853c4da8b9a2f1591a1b50e2e39c11e20984e92f8c6\",\"y\":\"4047660622423497c17682b686d7e685ba392f6c9f5f0b4445532096a303447b\"}]}],[{\"n\":\"13010173158918407480357961972061506572933617878293332040618341922085557262603492137627290080151272304984986742974562854648811965243708104573125205923498490658475729205101951641692870198963236953084012043096516569504782170459872747751715262356027338259844080787490221056310982055420810813704885421985189636638649025121976886732989974382479599220312000286022700868168030090156125831664869805273167686568906498296369922521988781852915777705670947212087385770233063295389461487648895402406264499877025150449737523800409959967374281726657242926040249744658597581615642020895188247480538948722275408286901290616189075960613\"},{\"n\":\"14107550317391369263575463507015434182923004620199500800448925994447321135196177984568045819936245893125423502854322785339519193156963117749573003448024256131633277379894492731953435879913802019305654271839378741523056036615760644794537058994163510522644745328335949388556091621824287287832718208894982246355699621216515700145199754292162726238226880977123697951320440492310065321112128693483342525896671001734837709922544910385719227735963737912270114963280659165453684525783897524791334895017889996564378823428084870601384092515056078959343761987414261335372085364008224029567030922285601471748180533450889855482181\"}],{\"x\":\"3fb18e0171552e90c2f375a72ba0675ef550549c9c94b7c8a4d13468f980dd3c\",\"y\":\"6b96b3354277eeac5b7074a4fca720a2b6350733177c825368a6ecd8f12beaea\"},\"35d5fb5a2bde95f1246415fb84e9e138c3d5d039fc977ca007e1b4d0ee339d1c\"]");
    println!("{}", wallet);
    let path = String::from("m/84'/0'/0'");
    let msg: Vec<u8> = hex::decode("657c698c5fd5d4657cd71889786149d8622cce4b01706fd1eb24405430a2cb7c").unwrap();
    let result = sdk::sign::sign(&nc, &wallet, &path, &msg, callback, null).expect("Failed to sign message");

    let sign_result = serde_json::to_string(&result).unwrap();
    println!("{}", sign_result);
}
