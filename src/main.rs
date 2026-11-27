use haskshield::{Config, run};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cfg = Config::from_env();
    let listener = TcpListener::bind(&cfg.listen).await?;
    println!(
        "haskshield listening on {} -> {} (max {} connections per IP)",
        cfg.listen, cfg.upstream, cfg.max_conn_per_ip
    );
    run(cfg, listener).await;
    Ok(())
}
