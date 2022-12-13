pub use crate::cpc_web3::CPCWeb3;

mod cpc_web3;
mod transport;
mod address;
mod utils;
pub mod hd;
pub mod accounts;

#[tokio::main]
async fn main() -> web3::Result<()> {
    let web3 = CPCWeb3::new("https://civilian.cpchain.io")?;
    let number = web3.block_number().await?;
    println!("{:?}", number);
    Ok(())
}
