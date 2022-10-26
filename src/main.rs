
#[tokio::main]
async fn main() -> web3::Result<()> {
    let web3 = cpc::CPCWeb3::new("https://civilian.cpchain.io")?;
    let number = web3.block_number().await?;
    println!("{:?}", number);
    Ok(())
}
