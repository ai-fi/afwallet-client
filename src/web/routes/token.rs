
#![allow(non_snake_case)]

use super::super::Result;
use rocket_contrib::json::Json;
use super::super::auth::jwt::Claims;

extern crate paillier;
extern crate reqwest;

extern crate hex;
extern crate serde_json;

use reqwest::Client;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SaveRequest {
    pub fileName: String, 
    pub share: String,
    pub salt: String,
    pub verification: String,
    pub version: String,
    pub ephemeralPublicKey: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct RetrieveRequest {
    pub a: String, 
    pub m1: String,
}


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Response<T> {
    pub code: i32,
    pub msg: String,
    pub data: Option<T>,
}

type SRPStep1ResponseData = String;
type SRPStep1Response = Response<SRPStep1ResponseData>;

type SaveResponseData = bool;
type SaveResponse = Response<SaveResponseData>;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct RetrieveResponseShareData {
    pub fileName: String,
    pub share: String,
    pub verification: String,
    pub salt: String,
    pub version: String,
    pub ephemeralPublicKey: String,
    pub otherOptions: Option<std::collections::HashMap<String, String>>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct RetrieveResponseData {
    pub m2: String,
    pub share: RetrieveResponseShareData,
}
type RetrieveResponse = Response<RetrieveResponseData>;




pub struct AFCloudClient {
    pub baseurl: String,
    client: Client,
}

impl AFCloudClient {
    pub fn new(baseurl: &str) -> AFCloudClient {
        
        let client = Client::builder().timeout(None).build().expect("Client::new()");
        // let client = Client::new();
        AFCloudClient{
            baseurl: String::from(baseurl),
            client: client
        }
    }

    pub fn get(&self, path: &str) -> Result<String> {
        let url = format!("{}/{}", self.baseurl, path);
        let res = self.client
            .get(&url)
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
            .post(&format!("{}/{}", self.baseurl, path))
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
}

#[get("/token/sss/share/srp/<filename>")]
pub fn srp(
    _claim: Claims,
    filename: String,
) -> Result<Json<SRPStep1Response>> {

    let client = AFCloudClient::new("https://registry.ai-fi.net");
    let path = format!("vpn/sss/share/srp/{}", filename);
    let respstr = client.get(&path)?;
    let resp: SRPStep1Response = serde_json::from_str(&respstr)?;
    return Ok(Json(resp));
}

#[post("/token/sss/share/save", format = "json", data = "<request>")]
pub fn save(
    _claim: Claims,
    request: Json<SaveRequest>,
) -> Result<Json<SaveResponse>> {
    let client = AFCloudClient::new("https://registry.ai-fi.net");
    let path = "vpn/sss/share/save";
    let respstr = client.post(&path, request.0)?;
    let resp: SaveResponse = serde_json::from_str(&respstr)?;
    return Ok(Json(resp));
}

#[post("/token/sss/share/retrieve/<filename>", format = "json", data = "<request>")]
pub fn retrieve(
    _claim: Claims,
    filename: String,
    request: Json<RetrieveRequest>,
) -> Result<Json<RetrieveResponse>> {
    let client = AFCloudClient::new("https://registry.ai-fi.net");
    let path = format!("vpn/sss/share/retrieve/{}", filename);
    let respstr = client.post(&path, request.0)?;
    //println!("{}", respstr);
    let resp: RetrieveResponse = serde_json::from_str(&respstr)?;
    return Ok(Json(resp));
}

#[post("/token/sss/share/update", format = "json", data = "<request>")]
pub fn update(
    _claim: Claims,
    request: Json<SaveRequest>,
) -> Result<Json<SaveResponse>> {
    let client = AFCloudClient::new("https://registry.ai-fi.net");
    let path = format!("vpn/sss/share/update");
    let respstr = client.post(&path, request.0)?;
    //println!("{}", respstr);
    let resp: SaveResponse = serde_json::from_str(&respstr)?;
    return Ok(Json(resp));
}