use failure::{err_msg, Error};

mod util;

// util

#[tokio::test]
async fn test_account() -> Result<(), Error> {
    let client = util::new_client().await?;
    let account = client.account().await?;
    assert!(account.sequence != 0);
    assert!(account.account_number != 0);
    Ok(())
}

#[tokio::test]
async fn test_version() -> Result<(), Error> {
    let client = util::new_client().await?;
    let version = client.version().await?;
    assert!(version != "");
    Ok(())
}

// tx

#[tokio::test]
async fn test_create_key_with_no_lease_info() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string();
    let val = util::random_string();
    client
        .create(
            &key,
            &val,
            util::gas_info(),
            Some(bluzelle::LeaseInfo::default()),
        )
        .await?;
    assert_eq!(client.read(&key).await?, val);
    Ok(())
}

#[tokio::test]
async fn test_creates_key_with_lease_info() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string();
    let val = util::random_string();
    client
        .create(&key, &val, util::gas_info(), util::lease_info())
        .await?;
    assert_eq!(client.read(&key).await?, val);
    Ok(())
}

#[tokio::test]
async fn test_creates_key_validates_gas_info() -> Result<(), Error> {
    let mut gas_info = bluzelle::GasInfo::default();
    gas_info.max_fee = Some(1);

    let mut client = util::new_client().await?;
    let key = util::random_string();
    let val = util::random_string();

    match client
        .create(&key, &val, gas_info, util::lease_info())
        .await
    {
        Ok(_) => Err(err_msg("did not raise error")),
        Err(_) => Ok(()),
    }
}

#[tokio::test]
async fn test_creates_key_with_symbols() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string() + " !\"#$%&'()*+,-.0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    let val = util::random_string();
    client
        .create(&key, &val, util::gas_info(), util::lease_info())
        .await?;
    match client.keys().await {
        Err(e) => Err(e),
        Ok(keys) => {
            for k in keys.iter() {
                if *k == key.to_string() {
                    return Ok(());
                }
            }
            Err(err_msg(format!(
                "key({}) was not found in ({:?})",
                key, keys
            )))
        }
    }
}

#[tokio::test]
async fn test_create_fails_if_key_contains_hash() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = "123/";
    let val = util::random_string();

    match client
        .create(&key, &val, util::gas_info(), util::lease_info())
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.to_string().contains("Key cannot contain a slash") {
                Ok(())
            } else {
                Err(err_msg("error was not raised"))
            }
        }
    }
}

#[tokio::test]
async fn test_update() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string();
    client
        .create(&key, "1", util::gas_info(), util::lease_info())
        .await?;
    client.update(&key, "2", util::gas_info(), None).await?;
    assert_eq!(client.read(&key).await?, "2");
    Ok(())
}

#[tokio::test]
async fn test_delete() -> Result<(), Error> {
    let key = util::random_string();
    let mut client = util::new_client().await?;
    client
        .create(&key, "1", util::gas_info(), util::lease_info())
        .await?;
    client.delete(&key, util::gas_info()).await?;
    assert!(client.has(&key).await?);
    Ok(())
}

#[tokio::test]
async fn test_rename() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string();
    let new_key = util::random_string();
    let val = util::random_string();

    assert!(!client.has(&key).await?);
    assert!(!client.has(&new_key).await?);

    client
        .create(&key, &val, util::gas_info(), util::lease_info())
        .await?;
    assert!(client.has(&key).await?);
    assert!(!client.has(&new_key).await?);

    client.rename(&key, &new_key, util::gas_info()).await?;
    assert!(!client.has(&key).await?);
    assert!(client.has(&new_key).await?);
    assert_eq!(client.read(&new_key).await?, val);
    Ok(())
}

#[tokio::test]
async fn test_delete_all() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string();
    let val = util::random_string();

    client
        .create(&key, &val, util::gas_info(), util::lease_info())
        .await?;
    assert!(client.keys().await?.len() != 0);
    client.delete_all(util::gas_info()).await?;
    assert_eq!(client.keys().await?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn test_multi_update() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string();

    client
        .create(&key, "1", util::gas_info(), util::lease_info())
        .await?;
    util::assert_kv_in_kvs(client.key_values().await?, &key, "1")?;
    let mut key_value = bluzelle::KeyValue::default();
    key_value.key = String::from(&key);
    key_value.value = String::from("2");
    let mut key_values: Vec<bluzelle::KeyValue> = Vec::new();
    key_values.push(key_value);
    client.multi_update(key_values, util::gas_info()).await?;
    util::assert_kv_in_kvs(client.key_values().await?, &key, "2")?;
    Ok(())
}

#[tokio::test]
async fn test_renew_lease() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string();
    client
        .create(&key, "1", util::gas_info(), util::lease_info())
        .await?;
    client
        .renew_lease(&key, util::gas_info(), util::lease_info())
        .await?;
    Ok(())
}

#[tokio::test]
async fn test_renew_all_leases() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string();
    client
        .create(&key, "1", util::gas_info(), util::lease_info())
        .await?;
    client
        .renew_lease_all(util::gas_info(), util::lease_info())
        .await?;
    Ok(())
}

// query

#[tokio::test]
async fn test_read() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string();
    let val = util::random_string();
    client
        .create(&key, &val, util::gas_info(), util::lease_info())
        .await?;
    let read_val = client.read(&key).await?;
    assert_eq!(val, read_val);
    Ok(())
}

#[tokio::test]
async fn test_has() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string();
    let val = util::random_string();
    assert!(!client.has(&key).await?);
    client
        .create(&key, &val, util::gas_info(), util::lease_info())
        .await?;
    assert!(client.has(&key).await?);
    Ok(())
}

#[tokio::test]
async fn test_count() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string();
    let val = util::random_string();
    let count = client.count().await?;
    client
        .create(&key, &val, util::gas_info(), util::lease_info())
        .await?;
    assert_eq!(client.count().await?, count + 1);
    Ok(())
}

#[tokio::test]
async fn test_keys() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string();
    let val = util::random_string();
    client
        .create(&key, &val, util::gas_info(), util::lease_info())
        .await?;
    util::assert_key_in_keys(client.keys().await?, &key)?;
    Ok(())
}

#[tokio::test]
async fn test_key_values() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string();
    let val = util::random_string();
    client
        .create(&key, &val, util::gas_info(), util::lease_info())
        .await?;
    util::assert_kv_in_kvs(client.key_values().await?, &key, &val)?;
    Ok(())
}

#[tokio::test]
async fn test_get_lease() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_get_n_shortest_leases() -> Result<(), Error> {
    Ok(())
}

// tx query

#[tokio::test]
async fn test_tx_read() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_tx_has() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_tx_count() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_tx_keys() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_tx_key_values() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_tx_get_lease() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_tx_get_n_shortest_leases() -> Result<(), Error> {
    Ok(())
}
