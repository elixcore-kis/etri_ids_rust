use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Local, TimeZone};
use log::{debug, error, info};
use pcap::{Capture, Linktype, Packet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet as PnetPacket;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

use crate::config::SuricataConfig;
use crate::dto::{generate_packet_stat_id, PacketStat, PcapProcessingInfo};
use crate::service::suricata::SuricataPcapProcessor;

pub struct PcapIDS {
    save_root_dir: String,
    interval: u64,
    max_buffer_size: usize,
    my_ip_set: HashSet<String>,
    suricata_processor: Arc<Mutex<SuricataPcapProcessor>>,
    log_period: u32,
    pcap_period: u32,
}

impl PcapIDS {
    pub fn new(
        save_root_path: String,
        interval: u64,
        max_buffer_size: usize,
        _target_interfaces: Option<String>,
        log_period: u32,
        pcap_period: u32,
        suricata_config: SuricataConfig,
        _filter: Option<String>,
    ) -> Result<Self> {
        info!("분석 파일 저장 경로: {}", save_root_path);

        let my_ip_set = Self::get_local_ips()?;
        info!("Local IPs: {:?}", my_ip_set);

        let temp_path = format!("{}/temp_pcap", save_root_path);
        fs::create_dir_all(&temp_path)?;

        // 임시 pcap 파일 정리
        if let Ok(entries) = fs::read_dir(&temp_path) {
            for entry in entries.flatten() {
                let _ = fs::remove_file(entry.path());
            }
        }

        let mut suricata_processor = SuricataPcapProcessor::new(suricata_config);
        suricata_processor.start()?;

        Ok(Self {
            save_root_dir: save_root_path,
            interval,
            max_buffer_size,
            my_ip_set,
            suricata_processor: Arc::new(Mutex::new(suricata_processor)),
            log_period,
            pcap_period,
        })
    }

    fn get_local_ips() -> Result<HashSet<String>> {
        let mut ip_set = HashSet::new();

        let ifaces = get_if_addrs::get_if_addrs()?;
        for iface in ifaces {
            if let get_if_addrs::IfAddr::V4(v4) = iface.addr {
                ip_set.insert(v4.ip.to_string());
            }
        }

        Ok(ip_set)
    }

    fn get_now_buffer_time(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        self.get_buffer_time(now)
    }

    fn get_buffer_time(&self, timestamp_sec: i64) -> i64 {
        timestamp_sec - (timestamp_sec % self.interval as i64)
    }

    pub async fn start_capture(
        &mut self,
        target_interfaces: Option<String>,
        filter: Option<String>,
    ) -> Result<()> {
        let interfaces = if let Some(targets) = target_interfaces {
            targets
                .split(',')
                .map(|s: &str| s.trim().to_string())
                .collect::<Vec<_>>()
        } else {
            vec!["any".to_string()]
        };

        let save_root = self.save_root_dir.clone();
        let interval_secs = self.interval;
        let my_ips = self.my_ip_set.clone();
        let log_period = self.log_period;
        let pcap_period = self.pcap_period;
        let suricata_ref = self.suricata_processor.clone();

        // 패킷 캡처 스레드 시작
        for iface in interfaces {
            let save_root_clone = save_root.clone();
            let filter_clone = filter.clone();
            let my_ips_clone = my_ips.clone();
            let suricata_clone = suricata_ref.clone();

            thread::spawn(move || {
                if let Err(e) = Self::capture_and_save_loop(
                    &iface,
                    filter_clone,
                    &save_root_clone,
                    interval_secs,
                    my_ips_clone,
                    suricata_clone,
                ) {
                    error!("Capture error on {}: {}", iface, e);
                }
            });
        }

        // 파일 정리 스케줄러
        let save_root_cleanup = save_root.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // 1시간마다
            loop {
                interval.tick().await;
                if let Err(e) = Self::file_organizer_static(&save_root_cleanup, log_period, pcap_period) {
                    error!("File organizer error: {}", e);
                }
            }
        });

        Ok(())
    }

    fn capture_and_save_loop(
        interface: &str,
        filter: Option<String>,
        save_root: &str,
        interval_secs: u64,
        my_ips: HashSet<String>,
        suricata: Arc<Mutex<SuricataPcapProcessor>>,
    ) -> Result<()> {
        info!("Starting capture on interface: {}", interface);

        let mut cap = Capture::from_device(interface)?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()?;

        if let Some(f) = &filter {
            if !f.is_empty() {
                cap.filter(f, true)?;
                info!("Applied filter: {}", f);
            }
        }

        let linktype = cap.get_datalink();

        loop {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let buffer_time = current_time - (current_time % interval_secs as i64);
            let next_buffer_time = buffer_time + interval_secs as i64;

            let temp_pcap_path = format!("{}/temp_pcap/{}.pcap", save_root, buffer_time);

            info!("Creating pcap file for buffer time {}: {}", buffer_time, temp_pcap_path);

            // pcap 파일 생성
            let mut savefile = cap.savefile(&temp_pcap_path)?;
            let mut packet_stats: HashMap<String, PacketStat> = HashMap::new();
            let mut packet_count = 0u64;

            // 현재 시간 슬롯 동안 패킷 캡처
            loop {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                if now >= next_buffer_time {
                    break;
                }

                match cap.next_packet() {
                    Ok(packet) => {
                        // pcap 파일에 저장
                        savefile.write(&packet);
                        packet_count += 1;

                        // 패킷 통계 수집
                        Self::process_packet_stats(&packet, &my_ips, &mut packet_stats, linktype);
                    }
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(e) => {
                        error!("Packet capture error: {}", e);
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }

            // 파일 저장 완료
            drop(savefile);

            info!("Buffer {} completed: {} packets captured", buffer_time, packet_count);

            // 별도 스레드에서 후처리 수행
            let save_root_clone = save_root.to_string();
            let suricata_clone = suricata.clone();
            let temp_path = temp_pcap_path.clone();

            thread::spawn(move || {
                if let Err(e) = Self::process_completed_buffer(
                    buffer_time,
                    &save_root_clone,
                    &temp_path,
                    packet_stats,
                    suricata_clone,
                ) {
                    error!("Buffer processing error: {}", e);
                }
            });
        }
    }

    fn process_packet_stats(
        packet: &Packet,
        my_ips: &HashSet<String>,
        stats: &mut HashMap<String, PacketStat>,
        linktype: Linktype,
    ) {
        let timestamp_ns = (packet.header.ts.tv_sec as i64 * 1_000_000_000)
            + (packet.header.ts.tv_usec as i64 * 1000);

        let data = packet.data;

        // Ethernet 또는 raw IP 처리
        let ip_data = if linktype == Linktype::ETHERNET {
            if let Some(eth) = EthernetPacket::new(data) {
                if eth.get_ethertype() == EtherTypes::Ipv4 {
                    Some(eth.payload().to_vec())
                } else {
                    None
                }
            } else {
                None
            }
        } else if linktype == Linktype(12) || linktype == Linktype(101) {
            // Raw IP (Linux cooked capture 또는 raw)
            Some(data.to_vec())
        } else {
            None
        };

        if let Some(ip_bytes) = ip_data {
            if let Some(ipv4) = Ipv4Packet::new(&ip_bytes) {
                let src_ip = ipv4.get_source().to_string();
                let dst_ip = ipv4.get_destination().to_string();
                let received = my_ips.contains(&dst_ip);
                let packet_size = data.len() as u64;

                match ipv4.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            let src_port = tcp.get_source();
                            let dst_port = tcp.get_destination();
                            let flags = tcp.get_flags();

                            let stat_id = generate_packet_stat_id(
                                src_port, dst_port, &src_ip, &dst_ip, received,
                            );

                            let stat = stats.entry(stat_id).or_insert_with(|| {
                                PacketStat::new(
                                    "TCP".to_string(),
                                    "Unknown".to_string(),
                                    "Unknown".to_string(),
                                    timestamp_ns,
                                    src_ip.clone(),
                                    src_port,
                                    dst_ip.clone(),
                                    dst_port,
                                )
                            });

                            stat.add_packet(
                                received,
                                timestamp_ns,
                                packet_size,
                                ipv4.get_total_length() as u64,
                                Some(flags),
                            );
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            let src_port = udp.get_source();
                            let dst_port = udp.get_destination();

                            let stat_id = generate_packet_stat_id(
                                src_port, dst_port, &src_ip, &dst_ip, received,
                            );

                            let stat = stats.entry(stat_id).or_insert_with(|| {
                                PacketStat::new(
                                    "UDP".to_string(),
                                    "UDP".to_string(),
                                    "Unknown".to_string(),
                                    timestamp_ns,
                                    src_ip.clone(),
                                    src_port,
                                    dst_ip.clone(),
                                    dst_port,
                                )
                            });

                            stat.add_packet(
                                received,
                                timestamp_ns,
                                packet_size,
                                udp.get_length() as u64,
                                None,
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn process_completed_buffer(
        buffer_time: i64,
        save_root: &str,
        temp_pcap_path: &str,
        packet_stats: HashMap<String, PacketStat>,
        _suricata: Arc<Mutex<SuricataPcapProcessor>>,
    ) -> Result<()> {
        let datetime = chrono::Local
            .timestamp_opt(buffer_time, 0)
            .single()
            .context("Invalid timestamp")?;

        let year = format!("{:04}", datetime.year());
        let month = format!("{:02}", datetime.month());
        let day = format!("{:02}", datetime.day());
        let save_date_dir = format!("{}/{}/{}", year, month, day);
        let save_file_name = datetime.format("%Y-%m-%dT%H:%M").to_string();

        let save_log_dir = format!("{}/log/{}", save_root, save_date_dir);
        let save_pcap_dir = format!("{}/pcap/{}", save_root, save_date_dir);

        fs::create_dir_all(&save_log_dir)?;
        fs::create_dir_all(&save_pcap_dir)?;

        // 로그 파일 저장
        let log_path = format!("{}/{}.log", save_log_dir, save_file_name);
        let mut log_file = File::create(&log_path)?;

        writeln!(log_file, "{}", PacketStat::log_header())?;
        for stat in packet_stats.values() {
            writeln!(log_file, "{}", stat.print())?;
        }

        info!("Saved log: {} ({} flows)", log_path, packet_stats.len());

        // pcap 파일 이동
        let new_pcap_path = format!("{}/{}.pcap", save_pcap_dir, save_file_name);
        if Path::new(temp_pcap_path).exists() {
            fs::rename(temp_pcap_path, &new_pcap_path)?;
            info!("Saved pcap: {}", new_pcap_path);
        }

        Ok(())
    }

    fn file_organizer_static(save_root: &str, log_period: u32, pcap_period: u32) -> Result<()> {
        info!("File Organize Start");

        if log_period > 0 {
            let cutoff = Local::now() - chrono::Duration::days(log_period as i64);
            let log_path = format!("{}/log", save_root);
            Self::delete_old_files_static(&log_path, &cutoff)?;
        }

        if pcap_period > 0 {
            let cutoff = Local::now() - chrono::Duration::days(pcap_period as i64);
            let pcap_path = format!("{}/pcap", save_root);
            Self::delete_old_files_static(&pcap_path, &cutoff)?;
        }

        Ok(())
    }

    fn delete_old_files_static(base_path: &str, cutoff: &DateTime<Local>) -> Result<()> {
        if !Path::new(base_path).exists() {
            return Ok(());
        }

        for entry in WalkDir::new(base_path).min_depth(1).max_depth(3) {
            let entry = entry?;
            if entry.file_type().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(value) = name.parse::<i32>() {
                        let path = entry.path();
                        let depth = path.components().count() - Path::new(base_path).components().count();

                        let should_delete = match depth {
                            1 => value < cutoff.year(),
                            2 => value < cutoff.month() as i32,
                            3 => value < cutoff.day() as i32,
                            _ => false,
                        };

                        if should_delete {
                            info!("Removing old directory: {:?}", path);
                            fs::remove_dir_all(path)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
