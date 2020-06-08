extern crate base64;
extern crate failure;
extern crate hex;
extern crate reqwest;
extern crate secp256k1;
extern crate serde;
extern crate sha2;
extern crate bip39;
// extern crate bech32;
extern crate ripemd160;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

// use failure;
use failure::Error;
use json;
use sha2::{Digest, Sha256};
use hdwallet::{KeyChain, DefaultKeyChain, ExtendedPrivKey, ExtendedPubKey};
// use std::fmt;
// use std::fs::File;
// use std::io;
use bech32::{self, FromBase32, ToBase32};
use ripemd160::{Ripemd160};

const TOKEN_NAME: &str = "ubnt";
const PUB_KEY_TYPE: &str = "tendermint/PubKeySecp256k1";
const DEFAULT_ENDPOINT: &str = "http://localhost:1317";
const DEFAULT_CHAIN_ID: &str = "bluzelle";
const HD_PATH: &str = "m/44'/118'/0'/0/0";
const ADDRESS_PREFIX: &str = "bluzelle";

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
pub struct AccountResponse {
    result: AccountResponseResult,
}

#[derive(Default, Deserialize, Debug)]
pub struct AccountResponseResult {
    value: Account,
}

#[derive(Default, Deserialize, Debug)]
pub struct Account {
    pub account_number: u64,
    pub address: String,
    pub coins: Vec<Coin>,
    pub public_key: String,
    pub sequence: u64,
}

#[derive(Default, Deserialize, Debug)]
pub struct Coin {
    pub denom: String,
    pub amount: String,
}

//

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct ValidateResponse {
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
pub struct TxSigHashPayload {
    account_number: String,
    chain_id: String,
    fee: TxFee,
    memo: String,
    msgs: Vec<TxMsg>,
    sequence: String,
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
    pub debug: bool,

    pub private_key_hex: String,
    pub public_key_base_64: String,
    pub address: String,
    pub bluzelle_account: Account,
}

impl Client {
    pub async fn create(&self, key: &str, value: &str) -> Result<bool, Error> {
        let body = json::object! {
            BaseReq: {
                chain_id: self.chain_id.to_string(),
                from: self.address.to_string(),
            },
            Key: key,
            Lease: String::from("0"),
            Owner: self.address.to_string(),
            UUID: self.uuid.to_string(),
            Value: value,
        };
        println!("~~~~> {}", json::stringify(body.clone()));
        let response: ValidateResponse = reqwest::Client::new()
            .post(&format!("{}/crud/create", self.endpoint))
            .body(json::stringify(body.clone()))
            .send()
            .await?
            .json()
            .await?;
        println!("res {:?}", response);

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
        let mut tx_body = TxRequest::default();
        tx_body.mode = String::from("block");
        tx_body.tx = tx;
        let body2 = serde_json::to_string(&tx_body)?;
        println!("payload ---> {}", body2.clone());
        let response2 = reqwest::Client::new()
            .post(&format!("{}/txs", self.endpoint))
            .json(&tx_body)
            .send()
            .await?;

        if !response2.status().is_success() {
            println!("error {:?}", response2.text().await?);
        } else {
            // retry broadcast
            println!("error {:?}", response2.text().await?);
        }

        Ok(true)
    }

    pub async fn sign(&self, fee: TxFee, memo: String, msg: Vec<TxMsg>) -> Result<TxSig, Error> {
        let mut sign_data = TxSigHashPayload::default();
        sign_data.account_number = self.bluzelle_account.account_number.to_string();
        sign_data.chain_id = self.chain_id.clone();
        sign_data.fee = fee;
        sign_data.memo = memo;
        sign_data.msgs = msg;
        sign_data.sequence = self.bluzelle_account.sequence.to_string();
        //
        println!("##^^^^^^^^^^^^^>{}", serde_json::to_string(&sign_data)?);
        let mut hasher = Sha256::new();
        hasher.input(serde_json::to_string(&sign_data)?);
        let hash = hasher.result();
        println!("##^^^^^^^^^^^^^>{}", hex::encode(&hash));
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
        println!("#########>{:?}", &ss);
        let sig = base64::encode(&hex::decode(ss)?);
        println!("--->{:?}", &sig);
        //
        let mut tx_sig = TxSig::default();
        tx_sig.pub_key = pub_key;
        tx_sig.signature = sig;
        tx_sig.account_number = self.bluzelle_account.account_number.to_string();
        tx_sig.sequence = self.bluzelle_account.sequence.to_string();

        Ok(tx_sig)
    }

    pub async fn read(&self, key: &str) -> Result<String, Error> {
        let response = reqwest::get(&format!(
            "{}/crud/read/{}/{}",
            self.endpoint, self.uuid, key
        ))
        .await?
        .text()
        .await?;
        //
        let response_json = json::parse(&response)?;
        //
        Ok(format!("{}", response_json["result"]["value"]))
    }

    pub async fn account(&self) -> Result<Account, Error> {
        let response: AccountResponse =
            reqwest::get(&format!("{}/auth/accounts/{}", self.endpoint, self.address))
                .await?
                .json()
                .await?;
        Ok(response.result.value)
    }
}

pub async fn new_client(
    mnemonic: String,
    endpoint: String,
    chain_id: String,
    uuid: String,
    debug: bool,
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
