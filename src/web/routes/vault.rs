

use rocket::State;

use super::super::Result;
use rocket_contrib::json::Json;

use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;
use super::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PairingInfo {
    //#[serde(rename(serialize = "server"))]
    pub server: String,
    //#[serde(rename(serialize = "authInfo"))]
    pub auth: String,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct VaultStatus {
    //#[serde(rename(serialize = "server"))]
    pub is_ready: bool,
    pub network: String,
    //#[serde(rename(serialize = "authInfo"))]
}

#[get("/vault/pairing_info")]
pub fn pairing_info() -> Result<Json<PairingInfo>> {
    // TODO: Add logic for health check
    let ip = crate::util::local_ip::get().unwrap();
    let server = format!("http://{}:{}", ip, 8000);
    let info = PairingInfo{
        server: server,
        auth: String::from(""),
    };
    Ok(Json(info))
}


#[get("/vault/status")]
pub fn vault_status(
    state: State<Config>,
    claim: Claims
) -> Result<Json<VaultStatus>> {
    let mut is_ready = false;

    let vault_wallet_ids_id = String::from("vault_wallet_ids_id");
    let result: Result<Option<Vec<String>>> = db::get(&state.db, &claim.sub, &vault_wallet_ids_id, &VaultStruct::VaultWalletIDs);
    if result.is_ok() {
        let option_wallet_ids = result.unwrap();
        if option_wallet_ids.is_some() {
            let wallet_ids = option_wallet_ids.unwrap();
            is_ready =  wallet_ids.len() > 0;
        }
    } 

    let vault_wallet_network = String::from("vault_wallet_network");
    let nw_result: Result<Option<String>> = db::get(&state.db, &claim.sub, &vault_wallet_network, &VaultStruct::VaultWalletNetwork);
    // let opt_network: Option<String> = match nw_result {
    //     Err(_e) => Some(String::from("testnet")),
    //     Ok(r) => r,
    // };
    // let network = match opt_network { 
    //     None => String::from("testnet"), 
    //     Some(s) => s, 
    // };

    let network: String = match nw_result {
        Err(_e) => String::from("bitcoin"),
        Ok(r) => match r { None => String::from("bitcoin"), Some(o) => o,},
    };

    let status = VaultStatus{
        is_ready: is_ready,
        network: network,
    };
    Ok(Json(status))
}

#[get("/vault/ids")]
pub fn list_vault_ids(
    state: State<Config>,
    claim: Claims
) -> Result<Json<Vec<String>>> {

    let vault_wallet_ids_id = String::from("vault_wallet_ids_id");
    let result: Vec<String> = db::get(&state.db, &claim.sub, &vault_wallet_ids_id, &VaultStruct::VaultWalletIDs)?
    .ok_or(format_err!("No data for such identifier {}", vault_wallet_ids_id))?;
    
    Ok(Json(result))
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VaultObject {
    pub subject: String,
    pub value: String,
    pub encoding: String,
}

#[get("/vault/list")]
pub fn list_vaults(
    state: State<Config>,
    claim: Claims
) -> Result<Json<Vec<VaultObject>>> {

    let vault_wallet_ids_id = String::from("vault_wallet_ids_id");
    let result: Vec<String> = db::get(&state.db, &claim.sub, &vault_wallet_ids_id, &VaultStruct::VaultWalletIDs)?
    .ok_or(format_err!("No data for such identifier {}", vault_wallet_ids_id))?;
    
    let mut vaults: Vec<VaultObject> = Vec::new();
    for id in result {
        let data: String =db::get(&state.db, &claim.sub, &id, &VaultStruct::VaultData)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

        vaults.push(VaultObject{
            subject: id, 
            value: data,
            encoding: String::from("plain"),
        });
    }

    Ok(Json(vaults))
}

#[get("/vault/data/<uuid>")]
pub fn vault_data(
    state: State<Config>,
    claim: Claims,
    uuid: String,
) -> Result<Json<String>> {
    let data: String =db::get(&state.db, &claim.sub, &uuid, &VaultStruct::VaultData)?
    .ok_or(format_err!("No data for such identifier {}", uuid))?;
    Ok(Json(data))
}



#[post("/vault/restore", format = "json", data = "<request>")]
pub fn restore(
    claim: Claims,
    state: State<Config>,
    request: Json<Vec<VaultObject>>,
) -> Result<Json<i32>> {

    let vault_wallet_ids_id = String::from("vault_wallet_ids_id");

    let mut wallet_ids: Vec<String> = Vec::new();
    for vault in request.0 {
        wallet_ids.push(vault.subject.clone());
        db::insert(
            &state.db,
            &claim.sub,
            &vault.subject.clone(),
            &VaultStruct::VaultData,
            &vault.value,
        )?;
    }

    db::insert(
        &state.db,
        &claim.sub,
        &vault_wallet_ids_id,
        &VaultStruct::VaultWalletIDs,
        &wallet_ids,
    )?;


    return Ok(Json(0));
}


#[get("/vault/switch_network/<network>")]
pub fn switch_network(
    claim: Claims,
    state: State<Config>,
    network: String,
) -> Result<Json<bool>> {
    let vault_wallet_network = String::from("vault_wallet_network");
    db::insert(&state.db, &claim.sub, &vault_wallet_network, &VaultStruct::VaultWalletNetwork, network)?;
    return Ok(Json(true));
}