extern crate base64;
extern crate bip39;
extern crate hex;
extern crate reqwest;
extern crate secp256k1;
extern crate serde;
extern crate sha2;
// extern crate bech32;
extern crate ripemd160;
extern crate serde_derive;
extern crate serde_json;
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;

use failure::{err_msg, Error};
use hdwallet::{DefaultKeyChain, ExtendedPrivKey, ExtendedPubKey, KeyChain};
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
// use std::fmt;
// use std::fs::File;
// use std::io;
use bech32::{self, FromBase32, ToBase32};
use log::{error, info, warn};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use ripemd160::Ripemd160;

const TOKEN_NAME: &str = "ubnt";
const PUB_KEY_TYPE: &str = "tendermint/PubKeySecp256k1";
const DEFAULT_ENDPOINT: &str = "http://localhost:1317";
const DEFAULT_CHAIN_ID: &str = "bluzelle";
const HD_PATH: &str = "m/44'/118'/0'/0/0";
const ADDRESS_PREFIX: &str = "bluzelle";
const BROADCAST_MAX_RETRIES: u64 = 10;
// const BROADCAST_RETRY_INTERVAL = time.Second;
const BLOCK_TIME_IN_SECONDS: u64 = 5;

const KEY_IS_REQUIRED: &str = "Key is required";
const VALUE_IS_REQUIRED: &str = "Value is required";
const KEY_CANNOT_CONTAIN_A_SLASH: &str = "Key cannot contain a slash";
const NEW_KEY_IS_REQUIRED: &str = "New Key is required";
const INVALID_LEASE_TIME: &str = "Invalid lease time";

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

#[derive(Default, Deserialize, Debug, Clone)]
pub struct HasResponse {
    result: HasResponseResult,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct HasResponseResult {
    has: bool,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct CountResponse {
    result: CountResponseResult,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct CountResponseResult {
    count: String,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct KeysResponse {
    result: KeysResponseResult,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct KeysResponseResult {
    keys: Vec<String>,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct KeyValuesResponse {
    result: KeyValuesResponseResult,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct KeyValuesResponseResult {
    keyvalues: Vec<KeyValue>,
}

#[derive(Default, Deserialize, Serialize, Debug, Clone)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct GetLeaseResponse {
    result: GetLeaseResponseResult,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct GetLeaseResponseResult {
    lease: String,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct GetNShortestLeasesResponse {
    result: GetNShortestLeasesResponseResult,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct GetNShortestLeasesResponseResult {
    keyleases: Vec<KeyLease>,
}

impl GetNShortestLeasesResponseResult {
    pub fn get_humanized_key_leases(
        &self,
    ) -> Result<Vec<GetNShortestLeasesResponseResultKeyLease>, Error> {
        let mut ret: Vec<GetNShortestLeasesResponseResultKeyLease> = Vec::new();
        for kl in self.keyleases.iter() {
            let lease: u64 = kl.lease.parse()?;
            let mut gkl = GetNShortestLeasesResponseResultKeyLease::default();
            gkl.key = String::from(kl.key.clone());
            gkl.lease = lease * BLOCK_TIME_IN_SECONDS;
            ret.push(gkl);
        }
        Ok(ret)
    }
}

#[derive(Default, Deserialize, Serialize, Debug, Clone)]
pub struct GetNShortestLeasesResponseResultKeyLease {
    pub key: String,
    pub lease: u64,
}

#[derive(Default, Deserialize, Serialize, Debug, Clone)]
pub struct KeyLease {
    pub key: String,
    pub lease: String,
}

//

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct TxValidateRequest {
    #[serde(rename = "BaseReq")]
    base_req: TxValidateRequestBaseReq,
    #[serde(rename = "Key", skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(rename = "KeyValues", skip_serializing_if = "Option::is_none")]
    key_values: Option<Vec<KeyValue>>,
    #[serde(rename = "Lease", skip_serializing_if = "Option::is_none")]
    lease: Option<String>,
    #[serde(rename = "NewKey", skip_serializing_if = "Option::is_none")]
    new_key: Option<String>,
    #[serde(rename = "Owner")]
    owner: String,
    #[serde(rename = "UUID")]
    uuid: String,
    #[serde(rename = "Value", skip_serializing_if = "Option::is_none")]
    value: Option<String>,
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

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
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
    #[serde(rename = "Key", skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(rename = "KeyValues", skip_serializing_if = "Option::is_none")]
    key_values: Option<Vec<KeyValue>>,
    #[serde(rename = "Lease", skip_serializing_if = "Option::is_none")]
    lease: Option<String>,
    #[serde(rename = "NewKey", skip_serializing_if = "Option::is_none")]
    new_key: Option<String>,
    #[serde(rename = "Owner")]
    owner: String,
    #[serde(rename = "UUID")]
    uuid: String,
    #[serde(rename = "Value", skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct TxSig {
    pub_key: TxSigPubKey,
    signature: String,
    account_number: String,
    sequence: String,
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
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
    #[serde(default)]
    pub max_fee: Option<u64>,
    #[serde(default)]
    pub max_gas: Option<u64>,
    #[serde(default)]
    pub gas_price: Option<u64>,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone, Copy)]
pub struct LeaseInfo {
    #[serde(default)]
    pub days: Option<i64>,
    #[serde(default)]
    pub hours: Option<i64>,
    #[serde(default)]
    pub minutes: Option<i64>,
    #[serde(default)]
    pub seconds: Option<i64>,
}

impl LeaseInfo {
    fn to_blocks(&self) -> i64 {
        let mut seconds = 0;
        if let Some(d) = self.days {
            seconds += d * 24 * 60 * 60;
        }
        if let Some(h) = self.hours {
            seconds += h * 60 * 60;
        }
        if let Some(m) = self.minutes {
            seconds += m * 60;
        }
        if let Some(s) = self.seconds {
            seconds += s;
        }
        seconds / (BLOCK_TIME_IN_SECONDS as i64)
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
        let response: VersionResponse = reqwest::get(&format!("{}/node_info", self.endpoint))
            .await?
            .json()
            .await?;
        Ok(response.application_version.version)
    }

    //

    pub async fn create(
        &mut self,
        key: &str,
        value: &str,
        gas_info: GasInfo,
        lease_info: Option<LeaseInfo>,
    ) -> Result<(), Error> {
        if key.is_empty() {
            return Err(err_msg(KEY_IS_REQUIRED));
        }
        validate_key(key)?;
        if value.is_empty() {
            return Err(err_msg(VALUE_IS_REQUIRED));
        }
        let mut lease: i64 = 0;
        if let Some(li) = lease_info {
            lease = li.to_blocks();
        }
        if lease < 0 {
            return Err(err_msg(INVALID_LEASE_TIME));
        }

        let mut tx = TxValidateRequest::default();
        tx.key = Some(String::from(key));
        tx.lease = Some(lease.to_string());
        tx.value = Some(String::from(value));

        self.tx("POST", "/crud/create", &mut tx, gas_info).await?;
        Ok(())
    }

    pub async fn update(
        &mut self,
        key: &str,
        value: &str,
        gas_info: GasInfo,
        lease_info: Option<LeaseInfo>,
    ) -> Result<(), Error> {
        if key.is_empty() {
            return Err(err_msg(KEY_IS_REQUIRED));
        }
        validate_key(key)?;
        if value.is_empty() {
            return Err(err_msg(VALUE_IS_REQUIRED));
        }

        let mut tx = TxValidateRequest::default();
        tx.key = Some(String::from(key));
        if let Some(li) = lease_info {
            let lease: i64 = li.to_blocks();
            if lease < 0 {
                return Err(err_msg(INVALID_LEASE_TIME));
            } else {
                tx.lease = Some(lease.to_string());
            }
        }

        tx.value = Some(String::from(value));
        self.tx("POST", "/crud/update", &mut tx, gas_info).await?;
        Ok(())
    }

    pub async fn delete(&mut self, key: &str, gas_info: GasInfo) -> Result<(), Error> {
        if key.is_empty() {
            return Err(err_msg(KEY_IS_REQUIRED));
        }
        validate_key(key)?;

        let mut tx = TxValidateRequest::default();
        tx.key = Some(String::from(key));

        self.tx("DELETE", "/crud/delete", &mut tx, gas_info).await?;
        Ok(())
    }

    pub async fn rename(
        &mut self,
        key: &str,
        new_key: &str,
        gas_info: GasInfo,
    ) -> Result<(), Error> {
        if key.is_empty() {
            return Err(err_msg(KEY_IS_REQUIRED));
        }
        validate_key(key)?;

        if new_key.is_empty() {
            return Err(err_msg(NEW_KEY_IS_REQUIRED));
        }
        validate_key(new_key)?;

        let mut tx = TxValidateRequest::default();
        tx.key = Some(String::from(key));
        tx.new_key = Some(String::from(new_key));

        self.tx("POST", "/crud/rename", &mut tx, gas_info).await?;
        Ok(())
    }

    pub async fn delete_all(&mut self, gas_info: GasInfo) -> Result<(), Error> {
        let mut tx = TxValidateRequest::default();
        self.tx("POST", "/crud/deleteall", &mut tx, gas_info)
            .await?;
        Ok(())
    }

    pub async fn multi_update(
        &mut self,
        key_values: Vec<KeyValue>,
        gas_info: GasInfo,
    ) -> Result<(), Error> {
        for key_value in key_values.iter() {
            if key_value.key.is_empty() {
                return Err(err_msg(KEY_IS_REQUIRED));
            }
            validate_key(&key_value.key)?;
            if key_value.value.is_empty() {
                return Err(err_msg(VALUE_IS_REQUIRED));
            }
        }
        let mut tx = TxValidateRequest::default();
        tx.key_values = Some(key_values);

        self.tx("POST", "/crud/multiupdate", &mut tx, gas_info)
            .await?;
        Ok(())
    }

    pub async fn renew_lease(
        &mut self,
        key: &str,
        gas_info: GasInfo,
        lease_info: Option<LeaseInfo>,
    ) -> Result<(), Error> {
        if key.is_empty() {
            return Err(err_msg(KEY_IS_REQUIRED));
        }
        validate_key(key)?;

        let mut tx = TxValidateRequest::default();
        tx.key = Some(String::from(key));
        if let Some(li) = lease_info {
            let lease: i64 = li.to_blocks();
            if lease < 0 {
                return Err(err_msg(INVALID_LEASE_TIME));
            } else {
                tx.lease = Some(lease.to_string());
            }
        }

        self.tx("POST", "/crud/renewlease", &mut tx, gas_info)
            .await?;
        Ok(())
    }

    pub async fn renew_lease_all(
        &mut self,
        gas_info: GasInfo,
        lease_info: Option<LeaseInfo>,
    ) -> Result<(), Error> {
        let mut tx = TxValidateRequest::default();
        if let Some(li) = lease_info {
            let lease: i64 = li.to_blocks();
            if lease < 0 {
                return Err(err_msg(INVALID_LEASE_TIME));
            } else {
                tx.lease = Some(lease.to_string());
            }
        }
        self.tx("POST", "/crud/renewleaseall", &mut tx, gas_info)
            .await?;
        Ok(())
    }

    pub async fn renew_all_leases(
        &mut self,
        gas_info: GasInfo,
        lease_info: Option<LeaseInfo>,
    ) -> Result<(), Error> {
        self.renew_lease_all(gas_info, lease_info).await
    }

    //

    pub async fn read(&self, key: &str) -> Result<String, Error> {
        let path = &format!("/crud/read/{}/{}", self.uuid, key);
        let text = self.query(path).await?;
        let ok_response: ReadResponse = match serde_json::from_str(&text) {
            Ok(res) => res,
            Err(_) => return Err(err_msg(text)),
        };
        Ok(ok_response.result.value)
    }

    pub async fn has(&self, key: &str) -> Result<bool, Error> {
        let path = &format!("/crud/has/{}/{}", self.uuid, key);
        let text = self.query(path).await?;
        let ok_response: HasResponse = serde_json::from_str(&text)?;
        Ok(ok_response.result.has)
    }

    pub async fn count(&self) -> Result<usize, Error> {
        let path = &format!("/crud/count/{}", self.uuid);
        let text = self.query(path).await?;
        let ok_response: CountResponse = match serde_json::from_str(&text) {
            Ok(res) => res,
            Err(_) => return Err(err_msg(text)),
        };
        let count: usize = ok_response.result.count.parse()?;
        Ok(count)
    }

    pub async fn keys(&self) -> Result<Vec<String>, Error> {
        let path = &format!("/crud/keys/{}", self.uuid);
        let text = self.query(path).await?;
        let ok_response: KeysResponse = match serde_json::from_str(&text) {
            Ok(res) => res,
            Err(_) => return Err(err_msg(text)),
        };
        Ok(ok_response.result.keys)
    }

    pub async fn key_values(&self) -> Result<Vec<KeyValue>, Error> {
        let path = &format!("/crud/keyvalues/{}", self.uuid);
        let text = self.query(path).await?;
        let ok_response: KeyValuesResponse = match serde_json::from_str(&text) {
            Ok(res) => res,
            Err(_) => return Err(err_msg(text)),
        };
        Ok(ok_response.result.keyvalues)
    }

    pub async fn get_lease(&self, key: &str) -> Result<u64, Error> {
        let path = &format!("/crud/getlease/{}/{}", self.uuid, key);
        let text = self.query(path).await?;
        let ok_response: GetLeaseResponse = match serde_json::from_str(&text) {
            Ok(res) => res,
            Err(_) => return Err(err_msg(text)),
        };
        let lease: u64 = ok_response.result.lease.parse()?;
        Ok(lease / BLOCK_TIME_IN_SECONDS)
    }

    pub async fn get_n_shortest_leases(
        &self,
        n: u64,
    ) -> Result<Vec<GetNShortestLeasesResponseResultKeyLease>, Error> {
        let path = &format!("/crud/getnshortestleases/{}/{}", self.uuid, n);
        let text = self.query(path).await?;
        let ok_response: GetNShortestLeasesResponse = match serde_json::from_str(&text) {
            Ok(res) => res,
            Err(_) => return Err(err_msg(text)),
        };
        let kls = ok_response.result.get_humanized_key_leases()?;
        Ok(kls)
    }

    //

    pub async fn tx_read(&mut self, key: &str, gas_info: GasInfo) -> Result<String, Error> {
        let mut tx = TxValidateRequest::default();
        tx.key = Some(key.to_string());
        //
        let response = self.tx("POST", "/crud/read", &mut tx, gas_info).await?;
        let value: String = serde_json::from_slice(&response)?;
        Ok(value)
    }

    //

    pub async fn query(&self, path: &str) -> Result<String, Error> {
        let url = format!("{}{}", self.endpoint, path);
        info!("query: {}", url);
        let response = reqwest::get(&url).await?;
        let text = response.text().await?;
        let error_response: ErrorResponse = match serde_json::from_str(&text) {
            Ok(res) => res,
            Err(_) => return Ok(text),
        };
        Ok(error_response.error)
    }

    pub async fn tx(
        &mut self,
        method: &str,
        endpoint: &str,
        tx: &mut TxValidateRequest,
        gas_info: GasInfo,
    ) -> Result<Vec<u8>, Error> {
        info!("tx: {} {}", method, endpoint);
        // self.broadcast_retries = 0;
        let mut response = self.tx_validate(method, endpoint, tx).await?;
        self.tx_broadcast(&mut response.value, gas_info).await
    }

    pub async fn tx_validate(
        &self,
        method: &str,
        endpoint: &str,
        tx: &mut TxValidateRequest,
    ) -> Result<TxValidateResponse, Error> {
        tx.base_req = TxValidateRequestBaseReq {
            chain_id: self.chain_id.to_string(),
            from: self.address.to_string(),
        };
        tx.owner = self.address.to_string();
        tx.uuid = self.uuid.to_string();
        let body = serde_json::to_string(&tx)?;
        let url = format!("{}/{}", self.endpoint, endpoint);
        info!("tx validate: {} {} {}", method, url, body.clone());
        let response: TxValidateResponse = match method {
            "DELETE" => {
                reqwest::Client::new()
                    .delete(&url)
                    .body(body.clone())
                    .send()
                    .await?
                    .json()
                    .await?
            }
            _ => {
                reqwest::Client::new()
                    .post(&url)
                    .body(body.clone())
                    .send()
                    .await?
                    .json()
                    .await?
            }
        };
        Ok(response)
    }

    pub async fn tx_broadcast(&mut self, tx: &mut Tx, gas_info: GasInfo) -> Result<Vec<u8>, Error> {
        // let mut tx  = Tx::default();
        // tx.msg = txn.value.msg;
        // tx.fee = txn.value.fee;

        // memo
        tx.memo = rand_string(32);

        // fee
        let mut gas: u64 = 0;
        if let Ok(f) = tx.fee.gas.parse() {
            gas = f;
        }
        let mut amount: u64 = 0;
        if tx.fee.amount.len() != 0 {
            if let Ok(a) = tx.fee.amount[0].amount.parse() {
                amount = a;
            }
        }
        let mut max_gas = 0;
        let mut max_fee = 0;
        let mut gas_price = 0;
        if let Some(a) = gas_info.max_gas {
            max_gas = a;
        }
        if let Some(a) = gas_info.max_fee {
            max_fee = a;
        }
        if let Some(a) = gas_info.gas_price {
            gas_price = a;
        }
        //
        if max_gas != 0 {
            gas = max_gas;
        }
        // if max_gas != 0 && gas > max_gas {
        //     gas = max_gas;
        // }
        if max_fee != 0 {
            amount = max_fee;
        } else if gas_price != 0 {
            amount = gas * gas_price;
        }

        let mut fee: TxFee = TxFee::default();
        fee.gas = gas.to_string();
        let mut fee_amount = TxFeeAmount::default();
        fee_amount.denom = String::from(TOKEN_NAME);
        fee_amount.amount = amount.to_string();
        fee.amount = Vec::new();
        fee.amount.push(fee_amount);
        tx.fee = fee;

        // signatures
        let sig = self.sign(&tx.fee, &tx.memo, &tx.msg).await?;
        tx.signatures = Vec::new();
        tx.signatures.push(sig);
        //
        let mut tx_request = TxRequest::default();
        tx_request.mode = String::from("block");
        tx_request.tx = (*tx).clone();
        //
        let body = serde_json::to_string(&tx_request)?;
        let url = format!("{}/txs", self.endpoint);
        info!("tx broadcast: POST {} {}", url, body.clone());
        let response: TxBroadcastResponse = reqwest::Client::new()
            .post(&url)
            .body(body.clone())
            .send()
            .await?
            .json()
            .await?;

        match response.code {
            None => {
                self.bluzelle_account.sequence += 1;
                match response.data {
                    None => {
                        let data: Vec<u8> = Vec::new();
                        return Ok(data);
                    }
                    Some(data) => {
                        return Ok(hex::decode(data)?);
                    }
                }
            }
            Some(code) => {
                // if response.raw_log.contains("signature verification failed") {
                //     self.broadcast_retries += 1;
                //     return;
                // }
                //
                // response.raw_log
                //
                return Err(err_msg(response.raw_log));
            }
        };
    }

    pub async fn sign(&self, fee: &TxFee, memo: &str, msg: &Vec<TxMsg>) -> Result<TxSig, Error> {
        let mut sign_data = TxBroadcastRequest::default();
        sign_data.account_number = self.bluzelle_account.account_number.to_string();
        sign_data.chain_id = self.chain_id.clone();
        sign_data.fee = (*fee).clone();
        sign_data.memo = String::from(memo);
        sign_data.msgs = (*msg).clone();
        sign_data.sequence = self.bluzelle_account.sequence.to_string();
        //
        let mut hasher = Sha256::new();
        hasher.input(serde_json::to_string(&sign_data)?);
        let hash = hasher.result();
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
        let sig = base64::encode(&hex::decode(ss)?);
        info!("signature {:?}", &sig);
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
        Err(_) => return Err(err_msg("cannot derive private key")),
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

fn rand_string(len: usize) -> String {
    thread_rng().sample_iter(&Alphanumeric).take(len).collect()
}

fn validate_key(key: &str) -> Result<(), Error> {
    if key.contains("/") {
        Err(err_msg(KEY_CANNOT_CONTAIN_A_SLASH))
    } else {
        Ok(())
    }
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
