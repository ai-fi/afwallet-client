

use bitcoin;
use bitcoin::consensus::encode::serialize;
use bitcoin::network::constants::Network;
use bitcoin::util::bip143::SighashComponents;
use bitcoin::{TxIn, TxOut};
use bitcoin::hashes::{sha256d, hex::FromHex};
use bitcoin::secp256k1::Signature;
use bitcoin::util::psbt::*;
extern crate serde_json;
use curv::{BigInt, FE, GE};
// use std::collections::HashMap;

// #[derive(Serialize, Deserialize)]
// pub struct WalletProfile {
//     pub id: String,
//     pub name: String,
//     pub threshold: u32,
//     pub parties: u32,
// }

// #[derive(Serialize, Deserialize)]
// pub struct WalletNetwork {
//     pub server: String,
//     pub jwt_token: String,
// }

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    pub network: String
}

// impl Clone for WalletProfile {
//     fn clone(&self) -> WalletProfile {
//         WalletProfile{
//             id: self.id.clone(),
//             name: self.name.clone(),
//             threshold: self.threshold.clone(),
//             parties: self.parties.clone()
//         }
//     }
// }

// impl Clone for WalletNetwork {
//     fn clone(&self) -> WalletNetwork {
//         WalletNetwork {
//             server: self.server.clone(),
//             jwt_token: self.jwt_token.clone(),
//         }
//     }
// }

impl Wallet {
    
    pub fn new(network: &str) -> Self {

        // serde_json::from_str(&config).unwrap();
        Wallet{
            network: String::from(network)
        }
    }

    pub fn from(network: String, json: String) -> Self {
        let mut wallet: Wallet = serde_json::from_str(&json).unwrap();
        wallet.network = network;
        wallet
    }

    pub fn parse_psbt(data: &[u8]) -> Option<PartiallySignedTransaction> {
        return None
    }

    // type conversion
    fn to_bitcoin_public_key(pk: curv::PK) -> bitcoin::util::key::PublicKey {
        let bz = pk.serialize();
        bitcoin::util::key::PublicKey::from_slice(&bz).unwrap()
        /*
        bitcoin::util::key::PublicKey {
            compressed: true,
            key: pk
        }*/
    }

    fn get_bitcoin_network(&self) -> Network {
        self.network.parse::<Network>().unwrap()
    }

    pub fn sign(mut psbt: &PartiallySignedTransaction) -> Option<PartiallySignedTransaction> {
        let transaction: bitcoin::Transaction = psbt.global.unsigned_tx.clone();
        let mut signed_transaction: bitcoin::Transaction = transaction.clone();

        let inputs = &psbt.inputs;
        let outputs = &psbt.outputs;

        let comp = SighashComponents::new(&transaction);

        /*
        let comp = SighashComponents::new(&transaction);
        let sig_hash = comp.sighash_all(
            &transaction.input[i],
            &bitcoin::Address::p2pkh(
                &to_bitcoin_public_key(pk),
                self.get_bitcoin_network()).script_pubkey(),
            (selected[i].value as u32).into(),
        );
        */


        return None
    }

    /*
    pub fn send(
        &mut self,
        to_address: String,
        amount_btc: f32,
        client_shim: &ClientShim,
    ) -> String {
        let selected = self.select_tx_in(amount_btc);
        if selected.is_empty() {
            panic!("Not enough fund");
        }

        let to_btc_adress = bitcoin::Address::from_str(&to_address).unwrap();

        let txs_in: Vec<TxIn> = selected
            .clone()
            .into_iter()
            .map(|s| bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: sha256d::Hash::from_hex(&s.tx_hash).unwrap(),
                    vout: s.tx_pos as u32,
                },
                script_sig: bitcoin::Script::default(),
                sequence: 0xFFFFFFFF,
                witness: Vec::default(),
            })
            .collect();

        let fees = 10_000;

        let amount_satoshi = (amount_btc * 100_000_000 as f32) as u64;

        let change_address = self.get_new_bitcoin_address();

        let total_selected = selected
            .clone()
            .into_iter()
            .fold(0, |sum, val| sum + val.value) as u64;

        let txs_out = vec![
            TxOut {
                value: amount_satoshi,
                script_pubkey: to_btc_adress.script_pubkey(),
            },
            TxOut {
                value: total_selected - amount_satoshi - fees,
                script_pubkey: change_address.script_pubkey(),
            },
        ];

        let transaction = bitcoin::Transaction {
            version: 0,
            lock_time: 0,
            input: txs_in,
            output: txs_out,
        };

        let mut signed_transaction = transaction.clone();

        for i in 0..transaction.input.len() {
            let address_derivation = self
                .addresses_derivation_map
                .get(&selected[i].address)
                .unwrap();

            let mk = &address_derivation.mk;
            let pk = mk.public.q.get_element();

            let comp = SighashComponents::new(&transaction);
            let sig_hash = comp.sighash_all(
                &transaction.input[i],
                &bitcoin::Address::p2pkh(
                    &to_bitcoin_public_key(pk),
                    self.get_bitcoin_network()).script_pubkey(),
                (selected[i].value as u32).into(),
            );

            let signature = ecdsa::sign(
                client_shim,
                BigInt::from_hex(&hex::encode(&sig_hash[..])),
                &mk,
                0,
                address_derivation.pos as i32,
                &self.private_share.id,
            ).unwrap();

            let mut v = BigInt::to_vec(&signature.r);
            v.extend(BigInt::to_vec(&signature.s));

            let mut sig_vec = Signature::from_compact(&v[..])
                .unwrap()
                .serialize_der()
                .to_vec();
            sig_vec.push(01);

            let pk_vec = pk.serialize().to_vec();

            signed_transaction.input[i].witness = vec![sig_vec, pk_vec];
        }

        let mut electrum = ElectrumxClient::new(ELECTRUM_HOST).unwrap();

        let raw_tx_hex = hex::encode(serialize(&signed_transaction));
        let txid = electrum.broadcast_transaction(raw_tx_hex.clone());

        txid.unwrap()
    }
    */
}