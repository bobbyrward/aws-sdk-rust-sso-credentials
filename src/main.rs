mod sso;

use aws_config::meta::region::ProvideRegion;
use aws_types::credentials::SharedCredentialsProvider;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let aws_config = aws_types::config::Config::builder()
        .credentials_provider(SharedCredentialsProvider::new(
            sso::SSOProvider::chained().await,
        ))
        .region(
            aws_config::default_provider::region::default_provider()
                .region()
                .await,
        )
        .build();

    let sts = aws_sdk_sts::Client::new(&aws_config);
    let caller_identity = sts.get_caller_identity().send().await?;

    println!("sts::get_caller_identity = {:?}", caller_identity);

    Ok(())
}
