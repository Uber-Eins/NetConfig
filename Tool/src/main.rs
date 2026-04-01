use Seshat::app;

#[tokio::main]
async fn main() {
    if let Err(error) = app::run().await {
        eprintln!("错误: {}", error);
        std::process::exit(1);
    }
}
