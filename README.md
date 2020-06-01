![](https://raw.githubusercontent.com/bluzelle/api/master/source/images/Bluzelle%20-%20Logo%20-%20Big%20-%20Colour.png)

### Getting started

Ensure you have a recent version of [Rust](https://www.rust-lang.org/) installed.

1. Add package in the `[dependencies]` section of your `Cargo.toml` config.

```
[dependencies]
bluzelle = { git = "https://github.com/vbstreetz/blzrs" }
```

4. Use:

```rust
extern crate bluzelle;

use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

    let mnemonic = "...";
    let endpoint = "...";
    let chain_id = "...";
    let uuid = "...";
    let debug = false;

    let client = bluzelle::new_client(mnemonic, endpoint, chain_id, uuid, debug).await?;

    let key: &str = "key";
    let value: &str = "value";
    let gas_info = bluzelle::GasInfo::default();
    gas_info.max_fee = 4000001;

    client.create(key, value, gas_info).await?;
    let read_value = client.read(key).await?;

    Ok(())
}
```

### Examples

Copy `.env.sample` to `.env` and configure if needed.

```
cp .env.sample .env
```

Then run the example:

```
    make example
```

### Tests

Configure env as described in the examples section above, and run:

```
    make test
```

### User Acceptance Testing

Please checkout the [UAT.md](https://github.com/vbstreetz/blzrs/blob/master/Readme.md) document for more details.

### Licence

MIT
