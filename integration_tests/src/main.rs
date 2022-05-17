use akd_integration_tests::fixture_generator;

#[tokio::main]
async fn main() {
    fixture_generator::run().await;
}
