use anyhow::Context as _;
use open62541::{ua, AsyncClient};
use open62541_sys::UA_NS0ID_SERVER_SERVERSTATUS_BUILDINFO;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let client = AsyncClient::new("opc.tcp://opcuademo.sterfive.com:26543").context("connect")?;

    let value = client
        .read_value(&ua::NodeId::ns0(UA_NS0ID_SERVER_SERVERSTATUS_BUILDINFO))
        .await?;

    println!("Value: {value:?}");

    Ok(())
}
