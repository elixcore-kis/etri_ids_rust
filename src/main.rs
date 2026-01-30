mod config;
mod dto;
mod service;
mod blacklist;

use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info};
use std::path::PathBuf;

use std::sync::Arc;
use config::Config;
use service::ids::PcapIDS;
use blacklist::blacklist::BlacklistManager;

#[derive(Parser, Debug)]
#[command(name = "ids_rust")]
#[command(about = "Rust-based IDS (Intrusion Detection System) using libpcap and Suricata", long_about = None)]
struct Args {
    #[arg(short = 'c', long = "config-file", help = "설정 파일 경로")]
    config_path: PathBuf,

    #[arg(
        short = 'i',
        long = "target-interface",
        help = "패킷 수집 대상 인터페이스 이름 목록 (예: -i ens18,ens24)"
    )]
    target_interfaces: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("ELIXCORE_IDS starting...");

    let args = Args::parse();

    if !args.config_path.exists() {
        error!("설정 파일이 존재하지 않습니다: {:?}", args.config_path);
        std::process::exit(-1);
    }

    let config = Config::load_from_file(&args.config_path)
        .context("Failed to load configuration")?;

    config.validate().context("Invalid configuration")?;

    info!("Configuration loaded from: {:?}", args.config_path);

    let mut blacklist_manager: Option<Arc<BlacklistManager>> = None;
    if let Some(blacklist_dir) = &config.blacklist_dir {
        let mut bm = BlacklistManager::new();
        if let Err(e) = bm.load_from_dir(blacklist_dir) {
            error!("Failed to load blacklists: {}", e);
        } else {
            info!("Blacklist manager initialized.");
            blacklist_manager = Some(Arc::new(bm));
        }
    }

    let target_interfaces = args
        .target_interfaces
        .or_else(|| config.interface.target.clone());

    if target_interfaces.is_none() {
        info!("NIC을 지정하지 않았습니다. 전체 NIC에 대해 캡처를 합니다.");
    }

    let filter = config.interface.filter.clone();
    if filter.is_none() {
        info!("필터가 지정되지 않았습니다.");
    } else {
        info!("Packet Capture Filter: {:?}", filter);
    }

    info!("저장 경로: {}", config.file.save_root_dir);
    info!("로그 보관 기간: {} days", config.file.log_period);
    info!("PCAP 보관 기간: {} days", config.file.pcap_period);

    let mut ids = PcapIDS::new(
        config.file.save_root_dir.clone(),
        60,
        3,
        target_interfaces.clone(),
        config.file.log_period,
        config.file.pcap_period,
        config.suricata.clone(),
        filter.clone(),
        blacklist_manager.clone(),
    )
    .context("Failed to initialize PcapIDS")?;

    info!("Starting packet capture...");
    ids.start_capture(target_interfaces, filter)
        .await
        .context("Failed to start capture")?;

    info!("IDS is running. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c()
        .await
        .context("Failed to listen for ctrl-c")?;

    info!("Shutting down...");

    Ok(())
}
