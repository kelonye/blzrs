extern crate base64;
extern crate hex;
extern crate reqwest;
extern crate secp256k1;
extern crate serde;
extern crate sha2;
extern crate bip39;
// extern crate bech32;
extern crate ripemd160;
extern crate serde_derive;
extern crate serde_json;
#[macro_use] extern crate log;

// use failure;
use failure::Error;
use sha2::{Digest, Sha256};
use hdwallet::{KeyChain, DefaultKeyChain, ExtendedPrivKey, ExtendedPubKey};
use serde_derive::{Serialize, Deserialize};
// use std::fmt;
// use std::fs::File;
// use std::io;
use bech32::{self, FromBase32, ToBase32};
use ripemd160::{Ripemd160};
use log::{info,warn,error};

const TOKEN_NAME: &str = "ubnt";
const PUB_KEY_TYPE: &str = "tendermint/PubKeySecp256k1";
const DEFAULT_ENDPOINT: &str = "http://localhost:1317";
const DEFAULT_CHAIN_ID: &str = "bluzelle";
const HD_PATH: &str = "m/44'/118'/0'/0/0";
const ADDRESS_PREFIX: &str = "bluzelle";
const BROADCAST_MAX_RETRIES: u64 = 10;
// const BROADCAST_RETRY_INTERVAL = time.Second;
const BLOCK_TIME_IN_SECONDS: u64 = 5;

//

// struct OptionError;

// impl std::error::Error for OptionError {}

// impl fmt::Display for OptionError {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "An Error Occurred, Please Try Again!") // user-facing output
//     }
// }

// impl fmt::Debug for OptionError {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "{{ file: {}, line: {} }}", file!(), line!()) // programmer-facing output
//     }
// }

// impl From<io::Error> for OptionError {
//     fn from(error: io::Error) -> Self {
//         OptionError {}
//     }
// }

//

#[derive(Default, Deserialize, Debug)]
pub struct ErrorResponse {
    error: String,
}

#[derive(Default, Deserialize, Debug)]
pub struct AccountResponse {
    result: AccountResponseResult,
}

#[derive(Default, Deserialize, Debug)]
pub struct AccountResponseResult {
    value: Account,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Account {
    pub account_number: u64,
    pub address: String,
    pub coins: Vec<Coin>,
    pub public_key: String,
    pub sequence: u64,
}


#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Coin {
    pub denom: String,
    pub amount: String,
}

#[derive(Default, Deserialize, Debug)]
pub struct VersionResponse {
    application_version: VersionResponseApplicationVersion,
}

#[derive(Default, Deserialize, Debug)]
pub struct VersionResponseApplicationVersion {
    version: String,
}


//

#[derive(Default, Deserialize, Debug, Clone)]
pub struct ReadResponse {
    result: ReadResponseResult,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct ReadResponseResult {
    value: String,
}

//

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct TxValidateRequest {
    #[serde(rename = "BaseReq")]
    base_req: TxValidateRequestBaseReq,
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Lease")]
    lease: String,
    #[serde(rename = "Owner")]
    owner: String,
    #[serde(rename = "UUID")]
    uuid: String,
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct TxValidateRequestBaseReq {
    from: String,
    chain_id: String,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct TxValidateResponse {
    value: Tx,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Tx {
    pub fee: TxFee,
    pub memo: String,
    pub msg: Vec<TxMsg>,
    #[serde(skip_deserializing)]
    pub signatures: Vec<TxSig>,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct TxFee {
    amount: Vec<TxFeeAmount>,
    gas: String,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct TxFeeAmount {
    amount: String,
    denom: String,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct TxMsg {
    #[serde(rename = "type")]
    type_reserved: String,
    value: TxMsgValue,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct TxMsgValue {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Lease")]
    lease: String,
    #[serde(rename = "Owner")]
    owner: String,
    #[serde(rename = "UUID")]
    uuid: String,
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct TxSig {
    pub_key: TxSigPubKey,
    signature: String,
    account_number: String,
    sequence: String,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct TxSigPubKey {
    #[serde(rename = "type")]
    type_reserved: String,
    value: String,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct TxBroadcastRequest {
    account_number: String,
    chain_id: String,
    fee: TxFee,
    memo: String,
    msgs: Vec<TxMsg>,
    sequence: String,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct TxBroadcastResponse {
	height: String,
	txhash: String,
	data: Option<String>,
	codespace: Option<String>,
	code: Option<u8>,
	raw_log: String,
	gas_wanted: String,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone, Copy)]
pub struct GasInfo {
    pub max_fee: u64,
    pub max_gas: u64,
    pub gas_price: u64,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone, Copy)]
pub struct LeaseInfo {
    pub days: u64,
    pub hours: u64,
    pub minutes: u64,
    pub seconds: u64,
}


impl LeaseInfo {
    fn to_blocks(&self) -> u64 {
        let mut seconds  = 0;
        seconds += self.days * 24 * 60 * 60;
        seconds += self.hours * 60 * 60;
        seconds += self.minutes * 60;
        seconds += self.seconds;
        seconds / BLOCK_TIME_IN_SECONDS
    }
}

//

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct TxRequest {
    mode: String,
    tx: Tx,
}

//

#[derive(Default)]
pub struct Client {
    pub mnemonic: String,
    pub endpoint: String,
    pub chain_id: String,
    pub uuid: String,

    private_key_hex: String,
    public_key_base_64: String,
    address: String,
    bluzelle_account: Account,
}

impl Client {
    pub async fn account(&self) -> Result<Account, Error> {
        let response: AccountResponse =
            reqwest::get(&format!("{}/auth/accounts/{}", self.endpoint, self.address))
                .await?
                .json()
                .await?;
        Ok(response.result.value)
    }

    pub async fn version(&self) -> Result<String, Error> {
        let response: VersionResponse =
            reqwest::get(&format!("{}/node_info", self.endpoint))
                .await?
                .json()
                .await?;
        Ok(response.application_version.version)
    }

    //

    pub async fn create(&self, key: &str, value: &str, gas_info: GasInfo, lease_info: LeaseInfo) -> Result<(), Error> {
        let mut tx = TxValidateRequest::default();
        tx.key = String::from(key);
        tx.lease = lease_info.to_blocks().to_string();
        tx.value = String::from(value);
        //
        self.tx(String::from("POST"), String::from("/crud/create"), &mut tx, gas_info).await?;
        Ok(())
    }

    //

    pub async fn read(&self, key: &str) -> Result<String, Error> {
        let path = &format!("/crud/read/{}/{}", self.uuid, key);
        let text = self.query(path).await?;
        let ok_response: ReadResponse = match serde_json::from_str(&text) {
            Ok(res) => res,
            Err(_) => return Ok(text)
        };
        Ok(ok_response.result.value)
    }

    //

    pub async fn tx_read(&self, key: String, gas_info: GasInfo) -> Result<String, Error> {
        let mut tx = TxValidateRequest::default();
        tx.key = key;
        //
        let response = self.tx(String::from("POST"), String::from("/crud/read"), &mut tx, gas_info).await?;
        let value: String = serde_json::from_slice(&response)?;
        Ok(value)
    }

    //

    pub async fn query(&self, path: &str) -> Result<String, Error> {
        let response = reqwest::get(&format!(
            "{}{}",
            self.endpoint, path
        ))
        .await?;
        let text = response.text().await?;
        let error_response: ErrorResponse = match serde_json::from_str(&text) {
            Ok(res) => res,
            Err(_) => return Ok(text)
        };
        Ok(error_response.error)
    }

    pub async fn tx(&self, method: String, endpoint: String, tx: &mut TxValidateRequest, gas_info: GasInfo) -> Result<Vec<u8>, Error> {
        // self.broadcast_retries = 0;
        let response = self.tx_validate(method, endpoint, tx).await?;
        info!("res {:?}", response);
        self.tx_broadcast(response, gas_info).await
    }

    pub async fn tx_validate(&self, method: String, endpoint: String, tx: &mut TxValidateRequest) -> Result<TxValidateResponse, Error> {
        tx.base_req = TxValidateRequestBaseReq{
            chain_id: self.chain_id.to_string(),
            from: self.address.to_string(),
        };
        tx.owner = self.address.to_string();
        tx.uuid = self.uuid.to_string();
        let body = serde_json::to_string(&tx)?;
        info!("~~~~> {}", body.clone());
        let response: TxValidateResponse = reqwest::Client::new()
            .post(&format!("{}/{}", self.endpoint, endpoint))
            .body(body.clone())
            .send()
            .await?
            .json()
            .await?;
        Ok(response)
    }

    pub async fn tx_broadcast(&self, response: TxValidateResponse, gas_info: GasInfo) -> Result<Vec<u8>, Error> {
        let mut fee: TxFee = TxFee::default();
        fee.gas = response.value.fee.gas;
        let mut fee_amount = TxFeeAmount::default();
        fee_amount.denom = String::from(TOKEN_NAME);
        fee_amount.amount = String::from("4000001");
        fee.amount = Vec::new();
        fee.amount.push(fee_amount);

        let msg = response.value.msg;
        let memo = String::from("fMRvgi4X8B1a6kaMkQPicxeeKEYjp2v7");

        let sig = self.sign(fee.clone(), memo.clone(), msg.clone()).await?;

        let mut tx = Tx::default();
        tx.fee = fee;
        tx.memo = memo;
        tx.msg = msg;
        tx.signatures = Vec::new();
        tx.signatures.push(sig);
        //
        let mut tx_request = TxRequest::default();
        tx_request.mode = String::from("block");
        tx_request.tx = tx;
        //
        let body = serde_json::to_string(&tx_request)?;
        info!("payload ---> {}", body.clone());
        let response: TxBroadcastResponse = reqwest::Client::new()
            .post(&format!("{}/txs", self.endpoint))
            .body(body.clone())
            .send()
            .await?
            .json()
            .await?;

            match response.code {
                None => {
                    match response.data {
                        None => {
                            let data: Vec<u8> = Vec::new();
                            return Ok(data);
                        },
                        Some(data) => {
                            // self.bluzelle_account.sequence += 1;
                            return Ok(hex::decode(data)?);
                        }
        
                    }
                },
                Some(code) => {
                    // if response.raw_log.contains("signature verification failed") {
                    //     self.broadcast_retries += 1;
                    //     return;
                    // }

                }

            }

            panic!(response.raw_log)
    }

    pub async fn sign(&self, fee: TxFee, memo: String, msg: Vec<TxMsg>) -> Result<TxSig, Error> {
        let mut sign_data = TxBroadcastRequest::default();
        sign_data.account_number = self.bluzelle_account.account_number.to_string();
        sign_data.chain_id = self.chain_id.clone();
        sign_data.fee = fee;
        sign_data.memo = memo;
        sign_data.msgs = msg;
        sign_data.sequence = self.bluzelle_account.sequence.to_string();
        //
        info!("##^^^^^^^^^^^^^>{}", serde_json::to_string(&sign_data)?);
        let mut hasher = Sha256::new();
        hasher.input(serde_json::to_string(&sign_data)?);
        let hash = hasher.result();
        info!("##^^^^^^^^^^^^^>{}", hex::encode(&hash));
        let message = secp256k1::Message::from_slice(&hash)?;

        let mut pub_key = TxSigPubKey::default();
        pub_key.type_reserved = String::from(PUB_KEY_TYPE);
        pub_key.value = self.public_key_base_64.clone();

        let priv_key_decoded = hex::decode(self.private_key_hex.clone())?;
        let secret_key = secp256k1::SecretKey::from_slice(&priv_key_decoded)?;

        let secp = secp256k1::Secp256k1::new();
        let rs = secp.sign(&message, &secret_key).serialize_compact();
        let (r, s) = rs.split_at(32);
        // let sig_string = std::str::from_utf8(&sig_bytes)?;
        let ry = hex::encode(r);
        let sy = hex::encode(s);
        // reverse_grapheme_clusters_in_place(&mut ry);
        // reverse_grapheme_clusters_in_place(&mut sy);
        let ss = &format!("{}{}", ry, sy);
        info!("#########>{:?}", &ss);
        let sig = base64::encode(&hex::decode(ss)?);
        info!("--->{:?}", &sig);
        //
        let mut tx_sig = TxSig::default();
        tx_sig.pub_key = pub_key;
        tx_sig.signature = sig;
        tx_sig.account_number = self.bluzelle_account.account_number.to_string();
        tx_sig.sequence = self.bluzelle_account.sequence.to_string();

        Ok(tx_sig)
    }
}

pub async fn new_client(
    mnemonic: String,
    endpoint: String,
    chain_id: String,
    uuid: String,
) -> Result<Client, Error> {
    let mut client = Client::default();
    client.mnemonic = mnemonic.clone();
    client.endpoint = endpoint;
    if client.endpoint.is_empty() {
        client.endpoint = String::from(DEFAULT_ENDPOINT);
    }
    client.chain_id = chain_id;
    if client.chain_id.is_empty() {
        client.chain_id = String::from(DEFAULT_CHAIN_ID);
    }
    client.uuid = uuid;

    let (private_key_hex, public_key_base_64, address) = derive_address(&mnemonic.clone())?;
    client.address = address;
    client.private_key_hex = private_key_hex;
    client.public_key_base_64 = public_key_base_64;
    client.bluzelle_account = client.account().await?;

    Ok(client)
}

fn derive_address(mnemonic_word: &str) -> Result<(String, String, String), Error> {
    let mnemonic = bip39::Mnemonic::from_phrase(mnemonic_word, bip39::Language::English)?;
    let seed = bip39::Seed::new(&mnemonic, "");
    let seed_bytes: &[u8] = seed.as_bytes();
    let private_extended_key: ExtendedPrivKey;

    match derive_private_key(&seed_bytes) {
        Ok(pk) => private_extended_key = pk,
        Err(e) => {
            panic!("{:?}", e);
        },
    };

    let private_key_hex = String::from(format!("{:x}", private_extended_key.private_key));
    let public_extended_key = ExtendedPubKey::from_private_key(&private_extended_key);
    let public_key_bytes = public_extended_key.public_key.serialize().to_vec();
    let public_key_base_64 = base64::encode(&public_key_bytes);

    let mut s_hasher = Sha256::new();
    s_hasher.input(public_key_bytes);
    let s = s_hasher.result();

    let mut r_hasher = Ripemd160::new();
    r_hasher.input(s);
    let r = r_hasher.result();

    let address = bech32::encode(ADDRESS_PREFIX, r.to_base32())?;

    Ok((private_key_hex, public_key_base_64, address))
}

fn derive_private_key(seed: &[u8]) -> Result<ExtendedPrivKey, hdwallet::error::Error> {
    let master_key = ExtendedPrivKey::with_seed(seed)?;
    let key_chain = DefaultKeyChain::new(master_key);
    let (extended_key, _derivation) = key_chain.derive_private_key(HD_PATH.into())?;
    Ok(extended_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_derives_address() {
        let (_private_key_hex, _public_key_base_64, address) = derive_address("around buzz diagram captain obtain detail salon mango muffin brother morning jeans display attend knife carry green dwarf vendor hungry fan route pumpkin car").unwrap();
        assert_eq!(address, "bluzelle1upsfjftremwgxz3gfy0wf3xgvwpymqx754ssu9");
    }
}
