

//use afwalletclient::*;
#![feature(map_first_last)]
#![recursion_limit = "128"]
#![feature(proc_macro_hygiene)]
#![feature(decl_macro)]

extern crate rocket;
extern crate config;
extern crate curv;
extern crate multi_party_ecdsa;
extern crate rocket_contrib;
extern crate uuid;
extern crate zk_paillier;
#[macro_use]
extern crate failure;

extern crate error_chain;

extern crate serde;
extern crate serde_json;

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
    /*
    let pk_vec: Vec<u8> = hex::decode("0252072a9cc7029ba1b2311f66d66ca187b3fb803f65e24746277fe8c329a80cb0").unwrap();
    // let pk = GE::from_bytes(&pubkey);
    let pk = bitcoin::PublicKey::from_slice(&pk_vec).unwrap();
    let network: bitcoin::network::constants::Network = "testnet".parse::<bitcoin::network::constants::Network>().unwrap();
    let address = bitcoin::Address::p2wpkh(&pk, network);
    println!("{:}", address);
    let pk_vec: Vec<u8> = hex::decode("026e0baa8877c082c464c6165a165c9fa3e41ee8e1d1494c6e54ba3ef2b15573c6").unwrap();
    // let pk = GE::from_bytes(&pubkey);
    let pk = bitcoin::PublicKey::from_slice(&pk_vec).unwrap();
    let network: bitcoin::network::constants::Network = "testnet".parse::<bitcoin::network::constants::Network>().unwrap();
    let address = bitcoin::Address::p2wpkh(&pk, network);
    println!("{:}", address);
    
    let pk_vec: Vec<u8> = hex::decode("0286035c385eef53d36dcc7623c63f5239ac7d2a467f2742e7bf780eb1989c9ba1").unwrap();
    // let pk = GE::from_bytes(&pubkey);
    let pk = bitcoin::PublicKey::from_slice(&pk_vec).unwrap();
    let network: bitcoin::network::constants::Network = "testnet".parse::<bitcoin::network::constants::Network>().unwrap();
    let address = bitcoin::Address::p2wpkh(&pk, network);
    println!("{:}", address);

    let pk_vec: Vec<u8> = hex::decode("03dc5cb5b15b50156af642ab53466248561d742b2e5b2fdc0f3a988b7f4b1c5b66").unwrap();
    // let pk = GE::from_bytes(&pubkey);
    let pk = bitcoin::PublicKey::from_slice(&pk_vec).unwrap();
    let network: bitcoin::network::constants::Network = "testnet".parse::<bitcoin::network::constants::Network>().unwrap();
    let address = bitcoin::Address::p2wpkh(&pk, network);
    println!("{:}", address);
    
    let pk_vec: Vec<u8> = hex::decode("02d1ca4eebd5958305ceb1a0e1190019e6a917c8fdc1d3a95126671a1aff036f39").unwrap();
    // let pk = GE::from_bytes(&pubkey);
    let pk = bitcoin::PublicKey::from_slice(&pk_vec).unwrap();
    let network: bitcoin::network::constants::Network = "testnet".parse::<bitcoin::network::constants::Network>().unwrap();
    let address = bitcoin::Address::p2wpkh(&pk, network);
    println!("{:}", address);
    
    let psbt_hex = "70736274ff0100710200000001a0ccaaaad5b014ddeb3ff8023a3ecf31c02c463da1f870796a05497d552cbf820100000000fdffffff02320000000000000016001437fe957c1d1975c87479d3ce2ac3c5579d78f4d9d885010000000000160014bf4bbea2d824ef578d7dc9968ff42cf52e05a1ba82f11b00000100f50200000000010196bbf42c6c1f3d0dae036061b0c3dadafe68b797c733b1f3b60afcdc6a7eaef70000000017160014578f248dbd6babe85b68efc264f32c27675b8cfefeffffff02a2c5100000000000160014e0f3b8cf1c96b09362ab78f9d7c8d9814d44393ca086010000000000160014c7dc8bceca0e4dc46708266a4b5d1833ecf4d96b0247304402204711fa799d6c67570986e28360cc9183d3baf0c90884e32968a658ab325180980220679c0034e8215324ec90b76a435338452a3753240f9a7e82b116d2e4ff6a7e33012103cd7e6fa75291ff788ecb678bba4af21472d442530a26da16ec283ceec10354e67ef11b00220602099b456492ab6918b0f87748daf39c2a94a0af0840ca888fffd4b5cfab127fa50c76f2321a00000000000000000022020388c882d5e3682513de49209c1580277d3501b7b3329bbd235e31258619ae786e0c76f2321a000000000100000000220203a3e7c634f9a39ff0e5ec483253ce447d94050a2e4f6349b3373f87fa38bac2240c76f2321a010000000000000000";
    let psbt = bitcoin::util::psbt::PartiallySignedTransaction::from_hex_string(psbt_hex);
    println!("{:?}", psbt);
    let psbt_hex = "70736274ff01009a0200000002a0ccaaaad5b014ddeb3ff8023a3ecf31c02c463da1f870796a05497d552cbf820100000000fdffffffa93e2afbe68acffb22d46c56039310db83cee51af799c496d78b86fb4447fec90000000000fdffffff02320000000000000016001437fe957c1d1975c87479d3ce2ac3c5579d78f4d93c0c030000000000160014bf4bbea2d824ef578d7dc9968ff42cf52e05a1ba87f11b00000100f50200000000010196bbf42c6c1f3d0dae036061b0c3dadafe68b797c733b1f3b60afcdc6a7eaef70000000017160014578f248dbd6babe85b68efc264f32c27675b8cfefeffffff02a2c5100000000000160014e0f3b8cf1c96b09362ab78f9d7c8d9814d44393ca086010000000000160014c7dc8bceca0e4dc46708266a4b5d1833ecf4d96b0247304402204711fa799d6c67570986e28360cc9183d3baf0c90884e32968a658ab325180980220679c0034e8215324ec90b76a435338452a3753240f9a7e82b116d2e4ff6a7e33012103cd7e6fa75291ff788ecb678bba4af21472d442530a26da16ec283ceec10354e67ef11b00220602099b456492ab6918b0f87748daf39c2a94a0af0840ca888fffd4b5cfab127fa50c76f2321a0000000000000000000100f502000000000101715decddd992a86d192771c77679dc9c34f152cccfab8d63fa066a73f22fc57e000000001716001420899fc9e4a85a7d5c4696bcf751cb9c98f94a9cfeffffff02a086010000000000160014c7dc8bceca0e4dc46708266a4b5d1833ecf4d96ba6b64d00000000001600140c7639a33fb35d95ac5e38901f178554d5cd94d30247304402200829ef84a89e63e5af808607b29af759a9125b264a7cfbdbf95a436d592c0ebc0220222254187835770098e38735856f48065d73961b2162a890e30e48913a5d0808012102b3d791a3e7eb085798d8448e41139f189945ecbade53ea1e9da0879e2118cf3e86f11b00220602099b456492ab6918b0f87748daf39c2a94a0af0840ca888fffd4b5cfab127fa50c76f2321a00000000000000000022020388c882d5e3682513de49209c1580277d3501b7b3329bbd235e31258619ae786e0c76f2321a000000000100000000220203a3e7c634f9a39ff0e5ec483253ce447d94050a2e4f6349b3373f87fa38bac2240c76f2321a010000000000000000";
    let psbt = bitcoin::util::psbt::PartiallySignedTransaction::from_hex_string(psbt_hex);
    println!("{:?}", psbt);
    */
    
    /*
    let psbt_hex = "70736274ff01009a0200000002a0ccaaaad5b014ddeb3ff8023a3ecf31c02c463da1f870796a05497d552cbf820100000000fdffffffa93e2afbe68acffb22d46c56039310db83cee51af799c496d78b86fb4447fec90000000000fdffffff02320000000000000016001437fe957c1d1975c87479d3ce2ac3c5579d78f4d93c0c030000000000160014bf4bbea2d824ef578d7dc9968ff42cf52e05a1ba87f11b000001011fa086010000000000160014c7dc8bceca0e4dc46708266a4b5d1833ecf4d96b220602099b456492ab6918b0f87748daf39c2a94a0af0840ca888fffd4b5cfab127fa50c76f2321a00000000000000000001011fa086010000000000160014c7dc8bceca0e4dc46708266a4b5d1833ecf4d96b220602099b456492ab6918b0f87748daf39c2a94a0af0840ca888fffd4b5cfab127fa50c76f2321a00000000000000000022020388c882d5e3682513de49209c1580277d3501b7b3329bbd235e31258619ae786e0c76f2321a000000000100000000220203a3e7c634f9a39ff0e5ec483253ce447d94050a2e4f6349b3373f87fa38bac2240c76f2321a010000000000000000";
    let psbt = bitcoin::util::psbt::PartiallySignedTransaction::from_hex_string(psbt_hex);
    println!("{:?}", psbt);


    let bz_vec = std::fs::read("/Users/mingtaichang/Desktop/psbts/1.psbt").unwrap();
    let psbt_hex = hex::encode(&bz_vec);
    let psbt = bitcoin::util::psbt::PartiallySignedTransaction::from_hex_string(&psbt_hex);
    println!("{:?}", psbt);
    
    let null: *mut c_void = std::ptr::null_mut();

    let nc = sdk::network::NetworkClient::new("{\"server\": \"http://127.0.0.1:8000\"}");
    let wallet = String::from("[\"b005db4f-c3cf-4f58-88fa-eceefcf30e76\",{\"u_i\":\"5af9be91745cb1faf114a3bfc93475a138481969749f794e4cbff3c3538aec06\",\"y_i\":{\"x\":\"1e199b3ffba956e0c1d612389626c405c9fcbb0589e8d4af277257bad6f43992\",\"y\":\"657c698c5fd5d4657cd71889786149d8622cce4b01706fd1eb24405430a2cb7c\"},\"dk\":{\"p\":\"102436931575215908658203758544580405192187269228355640162861178028649765883151729595079365648148253732035589929082645712436864984305260138327649770095562852806624345825579767655523755473074982051956259274594251398208240029887916522019272966806888071508555391049261047860399587853726252959533977359454072597359\",\"q\":\"137719376209865103603864297088871968058661589559917292221397605997582203197267480731806265637194330308669145126776956734686086512441372194357209105501308719587113339747646387473406248721754468562324898583325912377456619072070474800982530430846368761312643240010577103094850765256459716856586177508246563282059\"},\"ek\":{\"n\":\"14107550317391369263575463507015434182923004620199500800448925994447321135196177984568045819936245893125423502854322785339519193156963117749573003448024256131633277379894492731953435879913802019305654271839378741523056036615760644794537058994163510522644745328335949388556091621824287287832718208894982246355699621216515700145199754292162726238226880977123697951320440492310065321112128693483342525896671001734837709922544910385719227735963737912270114963280659165453684525783897524791334895017889996564378823428084870601384092515056078959343761987414261335372085364008224029567030922285601471748180533450889855482181\"},\"party_index\":2},{\"y\":{\"x\":\"3fb18e0171552e90c2f375a72ba0675ef550549c9c94b7c8a4d13468f980dd3c\",\"y\":\"6b96b3354277eeac5b7074a4fca720a2b6350733177c825368a6ecd8f12beaea\"},\"x_i\":\"4de56cca5b6c85533a538c3868e0dd67b7fb305735d6b759458b8a69fc3f9065\"},2,[{\"parameters\":{\"threshold\":1,\"share_count\":2},\"commitments\":[{\"x\":\"87f754025d1b84f24f3b7af040e5e89482239e9cbc8c0d35e22fe64acbeb8908\",\"y\":\"ffa2bf312332a132f5e6b0b4093a7b2246ce11d147b2b2010e9e8d336bed7ad9\"},{\"x\":\"f0429553a8e948bc2f37aeb34a9332e3564a000a51ac39c4d9dd463b4eb4018a\",\"y\":\"76e79dc34017736bf48349641a13b0abf5f5a69b768320d9f0fa1230b53313ad\"}]},{\"parameters\":{\"threshold\":1,\"share_count\":2},\"commitments\":[{\"x\":\"1e199b3ffba956e0c1d612389626c405c9fcbb0589e8d4af277257bad6f43992\",\"y\":\"657c698c5fd5d4657cd71889786149d8622cce4b01706fd1eb24405430a2cb7c\"},{\"x\":\"e3cde950682eca66246bb853c4da8b9a2f1591a1b50e2e39c11e20984e92f8c6\",\"y\":\"4047660622423497c17682b686d7e685ba392f6c9f5f0b4445532096a303447b\"}]}],[{\"n\":\"13010173158918407480357961972061506572933617878293332040618341922085557262603492137627290080151272304984986742974562854648811965243708104573125205923498490658475729205101951641692870198963236953084012043096516569504782170459872747751715262356027338259844080787490221056310982055420810813704885421985189636638649025121976886732989974382479599220312000286022700868168030090156125831664869805273167686568906498296369922521988781852915777705670947212087385770233063295389461487648895402406264499877025150449737523800409959967374281726657242926040249744658597581615642020895188247480538948722275408286901290616189075960613\"},{\"n\":\"14107550317391369263575463507015434182923004620199500800448925994447321135196177984568045819936245893125423502854322785339519193156963117749573003448024256131633277379894492731953435879913802019305654271839378741523056036615760644794537058994163510522644745328335949388556091621824287287832718208894982246355699621216515700145199754292162726238226880977123697951320440492310065321112128693483342525896671001734837709922544910385719227735963737912270114963280659165453684525783897524791334895017889996564378823428084870601384092515056078959343761987414261335372085364008224029567030922285601471748180533450889855482181\"}],{\"x\":\"3fb18e0171552e90c2f375a72ba0675ef550549c9c94b7c8a4d13468f980dd3c\",\"y\":\"6b96b3354277eeac5b7074a4fca720a2b6350733177c825368a6ecd8f12beaea\"},\"35d5fb5a2bde95f1246415fb84e9e138c3d5d039fc977ca007e1b4d0ee339d1c\"]");
    println!("{}", wallet);
    let path = String::from("m/0'/0'");
    let msg: Vec<u8> = hex::decode("657c698c5fd5d4657cd71889786149d8622cce4b01706fd1eb24405430a2cb7c").unwrap();
    let result = sdk::sign::sign(&nc, &wallet, &path, &msg, callback, null).expect("Failed to sign message");

    let sign_result = serde_json::to_string(&result).unwrap();
    println!("{}", sign_result);
    */
    let network: bitcoin::network::constants::Network = "testnet".parse::<bitcoin::network::constants::Network>().unwrap();

    let psbt_hex = "70736274ff0100550200000001369cdef3536cf5469d855943ea4bfb3e15556cbd9677f3735262e0d70bb444790100000000fdffffff01cf410f00000000001976a914344a0f48ca150ec2b903817660b9b68b13a6702688acc50c1c000001011f40420f0000000000160014bcf350cdc47b3300c663b5b2a00584098d0e9e36220602bbe54e02c4abda430caf8045a00925024d01cec10903cdb22f3363a15ee83f730cf0b9d4cd00000000000000000000";
    let psbt = bitcoin::util::psbt::PartiallySignedTransaction::from_hex_string(psbt_hex);
    let utx = psbt.clone().global.unsigned_tx;
    let tx_vec = bitcoin::consensus::serialize(&utx);
    let tx_hex = hex::encode(&tx_vec);
    println!("u_tx_hex: {:}", tx_hex);

    let nc = sdk::network::NetworkClient::new("{\"server\": \"http://127.0.0.1:8000\"}");
    let wallet = String::from(
        "[\"6f9ce304-bd74-4777-8726-66f3282c9d3c\",\"testnet\",{\"u_i\":\"2b6690b13b595209170cd7ee74861d3d0f30303fefc5884dc73d96ba0967ad7e\",\"y_i\":{\"x\":\"7b94817d2ae6ce2d3daf838157324632c1d9c0a5aca67200b06a2b64fb12fd34\",\"y\":\"2a96c9bcd079d6c5e3bb05504c56b4ca032a6520ca63fb5965bb96f9446432cd\"},\"dk\":{\"p\":\"171706611250479512353714867610027141643041216688568962527363495852339401744461807442832559908042945617180502724229989579303353371408971156720634697826632882304243327826962213233536408630395382832271897623798537361586317572311333069793903946099875469820487126485431037636709582237311423253477550029069278991971\",\"q\":\"132021588083207273591567537557030826215865928926779670427658562440702540678652326068913691571291254918674452546610388165555584367034255443246952925245643136591548870534167644957142899787617942308887952082682466748341929495902122706485792104262031756757289586498318611116554375643950805962540898130095817462411\"},\"ek\":{\"n\":\"22668979501674209962202631886116504239830896324045201470042642631697718210666166697844308479229611058977861564556255586338334185052154127680077120842215790384465647691526157645656999552698147681314578176834728953477066900424659234011240081066811486256998866471784554682813537963168578724063661234193027990999744312154078358540701717114717703122422628173866267537513312649606143179252811163094299028300161671439920016753882994475355447406443032998839879415152124238790966590374214698073003255146647687195546857908099169547925978286751459895611010414641402168964239665178189118340282125956392053250116511358053263302081\"},\"party_index\":2},{\"y\":{\"x\":\"95bf6343059a36cafd0130d5dcea44ea9f4d2b151717fa1e147a9951fa5b7fac\",\"y\":\"f3d21089c32df627aa28a659ed63859dbeb0970a0bab7dc47ed1feebfdc9a9d8\"},\"x_i\":\"df4d6c17e670c8e5b4b7bb8af79ce14c94081269d2d33af2ad3766238a5bb913\"},2,[{\"parameters\":{\"threshold\":1,\"share_count\":2},\"commitments\":[{\"x\":\"a7bbcdcac5a91b0c66c5f20161d9d93eaadf16129c5bf3ce738629e8777eb588\",\"y\":\"6ba0802d4a556cbbf66b7ecb5142ad0a040bee3cdcbc07e016676e102f994aa4\"},{\"x\":\"7f5b88876ca8aff74f732a0506def9dbf552865bdd9c17b4d995a00a7c827234\",\"y\":\"feb7837a045b97a1fc1ca5ca3d3d2c58e594ad65b91f1ebe742eb18dc0e20ad8\"}]},{\"parameters\":{\"threshold\":1,\"share_count\":2},\"commitments\":[{\"x\":\"7b94817d2ae6ce2d3daf838157324632c1d9c0a5aca67200b06a2b64fb12fd34\",\"y\":\"2a96c9bcd079d6c5e3bb05504c56b4ca032a6520ca63fb5965bb96f9446432cd\"},{\"x\":\"ccc96a52ba9635eeaf4cd40083d0034f4397c7fc622ec004e4fc956d3ecdfe71\",\"y\":\"9aa33a1bfd5d7d196367c0502e4853dcc81e1814290b8dbd1d101611cb7d853a\"}]}],[{\"n\":\"29781020305276558818449443575182267283334835378683346083525731036223318172098407351332268488877867809120777252447721492715706279463076783951900577319437027294509212927439854690323041458113563786155488249185590435446198887329700557023502449772043001621989901734064610946039840792172890820017125827191800726862027377135494336314309755144954899603772850012609287141333434699643264601675305676011552951749645429413685509981334889426370845122557839413251056457054704852663638253903505448240381827363659457931967469313846808508486559371699597999609637565967600319000927973254158706016332004359888466869697484668247159607569\"},{\"n\":\"22668979501674209962202631886116504239830896324045201470042642631697718210666166697844308479229611058977861564556255586338334185052154127680077120842215790384465647691526157645656999552698147681314578176834728953477066900424659234011240081066811486256998866471784554682813537963168578724063661234193027990999744312154078358540701717114717703122422628173866267537513312649606143179252811163094299028300161671439920016753882994475355447406443032998839879415152124238790966590374214698073003255146647687195546857908099169547925978286751459895611010414641402168964239665178189118340282125956392053250116511358053263302081\"}],{\"x\":\"95bf6343059a36cafd0130d5dcea44ea9f4d2b151717fa1e147a9951fa5b7fac\",\"y\":\"f3d21089c32df627aa28a659ed63859dbeb0970a0bab7dc47ed1feebfdc9a9d8\"},\"3de2fa5cb9be6a5b30e2d5196e66ae6b6fa0936fccc4d85254d053f9325fcbaa\"]"
    );
    println!("{}", wallet);
    
    let null: *mut c_void = std::ptr::null_mut();
    let signed_psbt = sdk::sign::sign_psbt(&nc, &wallet, network, &psbt, callback, null).expect("Failed to sign message");
    println!("signed_psbt:{:}",signed_psbt.clone().to_hex_string().unwrap());


    let p_signed_psbt: &mut bitcoin::util::psbt::PartiallySignedTransaction = &mut signed_psbt.clone();
    let tx = p_signed_psbt.clone().extract_tx();
    println!("signd_tx: {:?}", &tx);

    let tx_vec = bitcoin::consensus::serialize(&tx);
    let tx_hex = hex::encode(&tx_vec);
    println!("tx_hex: {:}", tx_hex);
}
