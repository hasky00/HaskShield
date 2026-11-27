use std::process::ExitCode;

use haskshield::{Config, run};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> ExitCode {
    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(why) => {
            eprintln!("haskshield: bad setting. {why}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match TcpListener::bind(&cfg.listen).await {
        Ok(listener) => listener,
        Err(why) => {
            eprintln!("haskshield: cannot listen on {}: {why}", cfg.listen);
            return ExitCode::FAILURE;
        }
    };
    println!("haskshield: listening on {} in front of {}", cfg.listen, cfg.upstream);
    println!(
        "haskshield: per IP {} connections, {} new per minute, {} messages per second",
        cfg.max_conn_per_ip, cfg.max_new_conn_per_min, cfg.msgs_per_sec
    );
    println!(
        "haskshield: events {}, {} per IP and {} per key per minute, proof of work {} ({} under pressure)",
        if cfg.verify_events { "verified" } else { "NOT verified" },
        cfg.events_per_min_per_ip,
        cfg.events_per_min_per_pubkey,
        cfg.min_pow,
        cfg.min_pow.max(cfg.pressure_pow),
    );
    run(cfg, listener).await;
    ExitCode::SUCCESS
}
