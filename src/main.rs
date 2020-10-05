
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
extern crate jsonwebtoken as jwt;
extern crate kv;
extern crate hex;

#[macro_use]
extern crate serde_derive;
pub mod ecdsa;
pub mod util;
pub mod web;
pub mod sdk;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_key_gen() {

        let nc = ecdsa::network::NetworkClient::new(&String::from("{\"server\": \"http://127.0.0.1:8001\"}"));
        let result = ecdsa::keygen::keygen(&nc, 1, 2);
        if result.is_err() {
            let err = result.err().unwrap();
            println!("{}", err);
        } else {
            let keygen = result.unwrap();
            let keygen_json = serde_json::to_string(&keygen).unwrap();
            println!("{}", keygen_json);
            // fs::write(env::args().nth(2).unwrap(), keygen_json).expect("Unable to save !");
        }
    }

    #[test]
    fn test_psbt() {
        // signed: 70736274ff0100520200000001668967b5000d6fd27a798808fe6b4076157fb80d823603e9ea84661521605b6b0000000000ffffffff01d1050f00000000001600142c4fc946e39e6f74115bc6954a46e03f6cf91d8b000000000001011f40420f000000000016001439a66ff5248d45f9b492ae3985a61d34686bc86a01086b024730440220087e8a69365a9ee4d795cb95a48a79a4d8bb70ff59b9e48eab5455fda1aca0b80220794efb7d72f8e232a814e36b2f25e88f2d52a66632f960c810e3ab1070bef925012102a671bac2f1f9d0d5181b4e5b1d9ae668ab3b139870cd7f04da107182d8b866710000
        // unsigned: 70736274ff0100520200000001668967b5000d6fd27a798808fe6b4076157fb80d823603e9ea84661521605b6b0000000000ffffffff01d1050f00000000001600142c4fc946e39e6f74115bc6954a46e03f6cf91d8b000000000001011f40420f000000000016001439a66ff5248d45f9b492ae3985a61d34686bc86a220602a671bac2f1f9d0d5181b4e5b1d9ae668ab3b139870cd7f04da107182d8b8667118fb7f7f4554000080000000800000008000000000000000000000
        // let res = sign_psbt("70736274ff0100520200000001668967b5000d6fd27a798808fe6b4076157fb80d823603e9ea84661521605b6b0000000000ffffffff01d1050f00000000001600142c4fc946e39e6f74115bc6954a46e03f6cf91d8b000000000001011f40420f000000000016001439a66ff5248d45f9b492ae3985a61d34686bc86a01086b024730440220087e8a69365a9ee4d795cb95a48a79a4d8bb70ff59b9e48eab5455fda1aca0b80220794efb7d72f8e232a814e36b2f25e88f2d52a66632f960c810e3ab1070bef925012102a671bac2f1f9d0d5181b4e5b1d9ae668ab3b139870cd7f04da107182d8b866710000");
        // let res = sign_psbt("70736274ff0100520200000001668967b5000d6fd27a798808fe6b4076157fb80d823603e9ea84661521605b6b0000000000ffffffff01d1050f00000000001600142c4fc946e39e6f74115bc6954a46e03f6cf91d8b000000000001011f40420f000000000016001439a66ff5248d45f9b492ae3985a61d34686bc86a220602a671bac2f1f9d0d5181b4e5b1d9ae668ab3b139870cd7f04da107182d8b8667118fb7f7f4554000080000000800000008000000000000000000000");
    }

    #[test]
    fn test_local_ip() {

        let ip = util::local_ip::get();
        println!("{}", ip.unwrap());
    }
}

fn test_psbt() {

    // signed: 70736274ff0100520200000001668967b5000d6fd27a798808fe6b4076157fb80d823603e9ea84661521605b6b0000000000ffffffff01d1050f00000000001600142c4fc946e39e6f74115bc6954a46e03f6cf91d8b000000000001011f40420f000000000016001439a66ff5248d45f9b492ae3985a61d34686bc86a01086b024730440220087e8a69365a9ee4d795cb95a48a79a4d8bb70ff59b9e48eab5455fda1aca0b80220794efb7d72f8e232a814e36b2f25e88f2d52a66632f960c810e3ab1070bef925012102a671bac2f1f9d0d5181b4e5b1d9ae668ab3b139870cd7f04da107182d8b866710000
    // unsigned: 70736274ff0100520200000001668967b5000d6fd27a798808fe6b4076157fb80d823603e9ea84661521605b6b0000000000ffffffff01d1050f00000000001600142c4fc946e39e6f74115bc6954a46e03f6cf91d8b000000000001011f40420f000000000016001439a66ff5248d45f9b492ae3985a61d34686bc86a220602a671bac2f1f9d0d5181b4e5b1d9ae668ab3b139870cd7f04da107182d8b8667118fb7f7f4554000080000000800000008000000000000000000000
    let res = bitcoin::util::psbt::PartiallySignedTransaction::from_hex_string("70736274ff0100520200000001668967b5000d6fd27a798808fe6b4076157fb80d823603e9ea84661521605b6b0000000000ffffffff01d1050f00000000001600142c4fc946e39e6f74115bc6954a46e03f6cf91d8b000000000001011f40420f000000000016001439a66ff5248d45f9b492ae3985a61d34686bc86a220602a671bac2f1f9d0d5181b4e5b1d9ae668ab3b139870cd7f04da107182d8b8667118fb7f7f4554000080000000800000008000000000000000000000");
    let tx1 = res.clone().extract_tx();
    let tx1_data = bitcoin::consensus::serialize(&tx1);
    let tx1_hex = hex::encode(tx1_data);
    println!("TX1: {}", tx1_hex);
    println!("PSBT1: {:?}", res);

    // let p: &mut bitcoin::util::psbt::PartiallySignedTransaction = &mut res.clone();
    // let inputs: &mut Vec<bitcoin::util::psbt::Input> = &mut p.inputs;
    // let input: &mut bitcoin::util::psbt::Input = inputs.first_mut().unwrap();
    // let sig = vec![1u8, 2, 3, 4];
    // let pk = vec![5u8, 6, 7, 8];
    // let mut vec1: Vec<Vec<u8>> = Vec::new();
    // vec1.push(sig);
    // vec1.push(pk);
    // input.final_script_witness = Some(vec1); 

    let res = bitcoin::util::psbt::PartiallySignedTransaction::from_hex_string("70736274ff0100520200000001668967b5000d6fd27a798808fe6b4076157fb80d823603e9ea84661521605b6b0000000000ffffffff01d1050f00000000001600142c4fc946e39e6f74115bc6954a46e03f6cf91d8b000000000001011f40420f000000000016001439a66ff5248d45f9b492ae3985a61d34686bc86a01086b024730440220087e8a69365a9ee4d795cb95a48a79a4d8bb70ff59b9e48eab5455fda1aca0b80220794efb7d72f8e232a814e36b2f25e88f2d52a66632f960c810e3ab1070bef925012102a671bac2f1f9d0d5181b4e5b1d9ae668ab3b139870cd7f04da107182d8b866710000");
    let tx2 = res.clone().extract_tx();
    let tx2_data = bitcoin::consensus::serialize(&tx2);
    let tx2_hex = hex::encode(tx2_data);
    println!("TX2: {}", tx2_hex);
    println!("PSBT2: {:?}", res);
    // let res = sign_psbt("70736274ff0100520200000001668967b5000d6fd27a798808fe6b4076157fb80d823603e9ea84661521605b6b0000000000ffffffff01d1050f00000000001600142c4fc946e39e6f74115bc6954a46e03f6cf91d8b000000000001011f40420f000000000016001439a66ff5248d45f9b492ae3985a61d34686bc86a01086b024730440220087e8a69365a9ee4d795cb95a48a79a4d8bb70ff59b9e48eab5455fda1aca0b80220794efb7d72f8e232a814e36b2f25e88f2d52a66632f960c810e3ab1070bef925012102a671bac2f1f9d0d5181b4e5b1d9ae668ab3b139870cd7f04da107182d8b866710000");
    
}

use std::process::exit;
use std::iter;
use qrcode::QrCode;

fn display_qrcode() {
    let ip = util::local_ip::get().unwrap();
    let server = format!("http://{}:{}", ip, 8000);
    let info = web::routes::vault::PairingInfo {
        server: server,
        auth: String::from(""),
    };
    let code = serde_json::to_string(&info).unwrap().into_bytes();

    let code = match QrCode::new(&code[..]) {
        Ok(code) => code,
        Err(e) => {
            println!("Can't generate QR code: {:?}", e);
            exit(1)
        }
    };

    let string = code.render()
        .light_color(' ')
        .dark_color('#')
        .build();

    let mut empty_str: String;
    let mut line_buffer = String::new();
    let mut lines = string.lines().into_iter();

    while let Some(line_top) = lines.next() {
        let line_bottom = match lines.next() {
            Some(l) => l,
            None => {
                empty_str = iter::repeat(' ').take(line_top.len()).collect();
                empty_str.as_str()
            }
        };

        for (top, bottom) in line_top.chars().zip(line_bottom.chars()) {
            let block = match (top, bottom) {
                ('#', '#') => '█',
                (' ', '#') => '▄',
                ('#', ' ') => '▀',
                _ => ' ',
            };
            line_buffer.push(block);
        }

        println!("{}", line_buffer);
        line_buffer.clear();
    }
}
fn main() {  
    let matches = clap::App::new("Ai-Fi Counterseal for Desktop")
        .version("0.0.1")
        .author("Ai-Fi.net, Incopration")
        .about("Ai-Fi Counterseal for Desktop")
        .arg(clap::Arg::with_name("open-browser")
            .short("b")
            .long("open-browser")
            .takes_value(false)
            .help("Open browser"))
        .get_matches();


    let run_psbt_test = false;
    if run_psbt_test {
        test_psbt();
    }

    display_qrcode();

    if matches.is_present("open-browser") {
        
        std::thread::spawn(move || {
            // std::thread::sleep_ms(1000);
            let result = webbrowser::open("http://127.0.0.1:8000");
            if result.is_err() {
                println!("Failed to launch browser, {:?}", result.err());
            }
        });
    }
    web::server::get_server().launch();
}
