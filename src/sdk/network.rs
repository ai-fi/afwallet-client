#![allow(non_snake_case)]

/// to run:
/// 1: go to rocket_server -> cargo run
/// 2: cargo run from PARTIES number of terminals
extern crate multi_party_ecdsa;
extern crate paillier;
extern crate reqwest;

extern crate hex;
extern crate serde_json;

use reqwest::Client;
use serde_json::{Value, Map};
use super::Result;


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct RequestMessage {
    pub uuid: String,
    pub message: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}


pub struct NetworkClient {
    pub connInfo: Map<String, Value>,
    client: Client,
}

impl NetworkClient {
    pub fn new(connstr: &str) -> NetworkClient {
        let parsed: Value = serde_json::from_str(connstr).expect("Invalid connstr");
        let connInfo: Map<String, Value> = parsed.as_object().expect("Invalid connjson").clone();
        connInfo.get("server").expect("Not have a server address");
        
        let client = Client::builder().timeout(None).build().expect("Client::new()");
        // let client = Client::new();
        NetworkClient{
            connInfo: connInfo,
            client: client
        }
    }
        
    fn get_server(&self) -> String {
        let server = self.connInfo.get("server").unwrap().as_str().unwrap();
        String::from(server)
    }

    pub fn get(&self, path: &str) -> Result<String> {
        let res = self.client
            .get(&format!("{}/{}", self.get_server(), path))
            .send();
        
        let mut response = match res {
            Ok(r) => r,
            Err(e) => return Err(format_err!("Invalid Response: {:}", e))
        };

        match response.text() {
            Ok(r) => return Ok(r),
            Err(e) => return Err(format_err!("Invalid Response: {:}", e))
        };
    }

    pub fn post<T>(&self, path: &str, body: T) -> Result<String> 
        where T: serde::ser::Serialize,
    {
        let res = self.client
            .post(&format!("{}/{}", self.get_server(), path))
            .json(&body)
            .send();
        
        let mut response = match res {
            Ok(r) => r,
            Err(e) => return Err(format_err!("Invalid Response: {:}", e))
        };

        match response.text() {
            Ok(r) => return Ok(r),
            Err(e) => return Err(format_err!("Invalid Response: {:}", e))
        };
    }

    pub fn keygen(&self, body: &RequestMessage) -> Result<(String, String)> {
        let res = self.post("api/ecdsa/keygen", body);
        let text = match res {
            Ok(r) => r,
            Err(e) => return Err(e),
        };
        //println!("{}",text);
        let (uuid, msg): (String, String) = serde_json::from_str(&text)?;
        Ok((uuid, msg))
    }

    pub fn sign(&self, body: &RequestMessage) -> Result<(String, String)> {
        let res = self.post("api/ecdsa/sign", body);
        let text = match res {
            Ok(r) => r,
            Err(e) => return Err(e),
        };
        let (uuid, msg): (String, String) = serde_json::from_str(&text)?;
        Ok((uuid, msg))
    }

}