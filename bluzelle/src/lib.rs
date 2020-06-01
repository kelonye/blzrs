extern crate base64;
extern crate failure;
extern crate hex;
extern crate reqwest;
extern crate secp256k1;
extern crate serde;
extern crate sha2;
extern crate unicode_reverse;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use failure::Error;
use json;
use sha2::{Digest, Sha256, Sha512};
use unicode_reverse::reverse_grapheme_clusters_in_place;

const TOKEN_NAME: &str = "ubnt";
const PUB_KEY_TYPE: &str = "tendermint/PubKeySecp256k1";

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

    pub priv_key: String,
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
        pub_key.value = String::from("A6ey15h5CRid3vxRdp8zfZGpsbCN9fPN7hRpSdxRoEa+");

        let priv_key = "94442e5b866840737b4d43e45e34efc0a773c4b20c6e3de224c35eae4c9b8c6c";
        let priv_key_decoded = hex::decode(priv_key)?;
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
    let (priv_key, address) = derive_address(&mnemonic);
    println!(
        "mnemonic({}) endpoint({}) chain_id({}) uuid({}) debug({}) address({})",
        mnemonic, endpoint, chain_id, uuid, debug, address
    );
    let mut client = Client::default();
    client.mnemonic = mnemonic;
    client.endpoint = endpoint;
    client.chain_id = String::from("bluzelle");
    client.uuid = uuid;
    client.address = String::from("bluzelle1upsfjftremwgxz3gfy0wf3xgvwpymqx754ssu9");

    client.bluzelle_account = client.account().await?;
    Ok(client)
}

fn derive_address(mnemonic: &str) -> (&str, &str) {
    (mnemonic, "bluzelle1upsfjftremwgxz3gfy0wf3xgvwpymqx754ssu9")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_derives_address() {
        let (_private_key, address) = derive_address("around buzz diagram captain obtain detail salon mango muffin brother morning jeans display attend knife carry green dwarf vendor hungry fan route pumpkin car");
        assert_eq!(address, "bluzelle1upsfjftremwgxz3gfy0wf3xgvwpymqx754ssu9");
    }
}
