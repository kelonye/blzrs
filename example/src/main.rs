extern crate bluzelle;
extern crate dotenv;

use dotenv::dotenv;
use std::env;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

    let mnemonic = read_env(String::from("MNEMONIC"));
    let endpoint = read_env(String::from("ENDPOINT"));
    let chain_id = read_env(String::from("CHAIN_ID"));
    let uuid = read_env(String::from("UUID"));
    let debug = read_env_bool(String::from("DEBUG"));

    let client = bluzelle::new_client(mnemonic, endpoint, chain_id, uuid, debug).await?;

    let key: &str = "1590919018y";
    let value: &str = "value";

    // println!("account");
    // let account = client.account().await?;
    // println!("account({:?})", account);

    println!("creating key({})", key);
    client.create(key, value).await?;
    println!("created key({})", key);

    // println!("reading key({})", key);
    // let value2 = client.read(key).await?;
    // println!("read key({}) value({:?})", key, value2);

    Ok(())
}

fn read_env(key: String) -> String {
    match env::var(key) {
        Ok(val) => val,
        Err(_e) => String::from(""),
    }
}

fn read_env_bool(key: String) -> bool {
    match env::var(key) {
        Ok(_val) => true,
        Err(_e) => false,
    }
}
