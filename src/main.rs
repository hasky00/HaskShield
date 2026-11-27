use haskshield::{Config, run};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cfg = Config::from_env();
    let listener = TcpListener::bind(&cfg.listen).await?;
    println!(
        "haskshield listening on {} -> {} ({} connections and {} messages/s per IP)",
        cfg.listen, cfg.upstream, cfg.max_conn_per_ip, cfg.msgs_per_sec
    );
    run(cfg, listener).await;
    Ok(())
}
