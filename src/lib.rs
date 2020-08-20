
// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[macro_use] 
extern crate  failure;
#[macro_use]
extern crate serde_derive;
mod ecdsa;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
}



pub fn error_to_c_string(e: failure::Error) -> *mut c_char {
    CString::new(format!("Error: {}", e.to_string())).unwrap().into_raw()
}

pub fn parse_address_path(path: &str) -> Option<Vec<i32>> {

    if !path.starts_with("m") {
        return None
    }

    let new_path = path.replace("'", "").replace("m/", "");


    let components: Vec<&str> = new_path.split("/").collect();
    let mut res: Vec<i32> = Vec::new();
    for component in components.iter() {
        let num = component.parse::<i32>().unwrap();
        res.push(num);
    }

    return Some(res);
}

pub fn ecdsa_keygen(server: &str, token: &str, threshold: i32, parties: i32) {
    
}

pub fn ecdsa_sign(server: &str, token: &str, threshold: i32, parties: i32) {
    
}

#[no_mangle]
pub extern "C" fn connect_server(c_endpoint: *const c_char, c_auth_token: *const c_char) -> bool {
    let raw_endpoint = unsafe { CStr::from_ptr(c_endpoint) };
    let endpoint = match raw_endpoint.to_str() {
        Ok(s) => s,
        Err(e) => return false,
    };
    let raw_auth_token = unsafe { CStr::from_ptr(c_auth_token) };
    let auth_token = match raw_auth_token.to_str() {
        Ok(s) => s,
        Err(e) => return false,
    };
    
    true
}

#[no_mangle]
pub extern "C" fn c_sign_psbt(c_psbt: *const c_char) -> *mut c_char {
    let raw_psbt = unsafe { CStr::from_ptr(c_psbt) };
    let psbt = match raw_psbt.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw endpoint failed: {}", e)),
    };
    let signature_json = sign_psbt(psbt);
    CString::new(signature_json.to_owned()).unwrap().into_raw()
}

pub fn sign_psbt(hex: &str) -> String {
    let psbt = bitcoin::util::psbt::PartiallySignedTransaction::from_hex_string(hex);
    let tx = psbt.extract_tx();
    let signed_psbt = bitcoin::util::psbt::PartiallySignedTransaction::from_unsigned_tx(tx).unwrap();
    //let mut s = String::new();
    //let mut buf = Vec::new();
    //let r: Result<usize, _> = psbt.consensus_encode(buf);
    let str1 = signed_psbt.to_hex_string().unwrap();
    return  str1;
}


#[cfg(test)]
mod tests {
    
    #[test]
    fn test_parse_address_path(){
        let path = "m/84'/0'/0'";
        let result = super::parse_address_path(path).unwrap();
        
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], 84);
        assert_eq!(result[1], 0);
        assert_eq!(result[2], 0);
    }
}