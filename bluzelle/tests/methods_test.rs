use failure::Error;

mod util;

#[tokio::test]
async fn account() -> Result<(), Error> {
    let client = util::new_client().await?;
    let account = client.account().await?;
    println!("sequence: {}", account.sequence);
    assert!(account.sequence != 0);
    assert!(account.account_number != 0);
    Ok(())
}

#[tokio::test]
async fn version() -> Result<(), Error> {
    let client = util::new_client().await?;
    let version = client.version().await?;
    assert!(version != "");
    Ok(())
}

// query

#[tokio::test]
async fn key() -> Result<(), Error> {
    let client = util::new_client().await?;
    let key = util::random_string()?;
    let val = util::random_string()?;
    client.create(&key, &val, util::gas_info(), util::lease_info()).await?;
    let read_val = client.read(&key).await?;
    assert_eq!(val, read_val);
    Ok(())
}
