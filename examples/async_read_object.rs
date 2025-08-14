use std::str::FromStr as _;

use anyhow::Context as _;
use open62541::{ua, AsyncClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let client = AsyncClient::new("opc.tcp://opcuademo.sterfive.com:26543").context("connect")?;

    let value = client
        .read_value(&ua::NodeId::from_str("ns=1;s=BottleFiller-Status-Product").unwrap())
        .await?
        .into_value()
        .unwrap();

    println!("Value: {value:?}");

    Ok(())
}
