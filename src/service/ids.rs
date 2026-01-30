use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Local, TimeZone};
use log::{debug, error, info, warn};
use pcap::{Capture, Linktype, Packet, PacketHeader};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet as PnetPacket;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::{Array, HashMap as BpfHashMap, MapData};
use aya::programs::{Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::Ebpf;
use bytes::BytesMut;
use tokio::sync::mpsc;

use crate::blacklist::blacklist::BlacklistManager;
use crate::config::SuricataConfig;
use crate::dto::{generate_packet_stat_id, PacketEvent, PacketStat, PcapProcessingInfo};
use crate::service::suricata::SuricataPcapProcessor;

pub struct PcapIDS {
    save_root_dir: String,
    interval: u64,
    max_buffer_size: usize,
    my_ip_set: HashSet<String>,
    suricata_processor: Arc<Mutex<SuricataPcapProcessor>>,
    log_period: u32,
    pcap_period: u32,
    blacklist_manager: Option<Arc<BlacklistManager>>,
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
        blacklist_manager: Option<Arc<BlacklistManager>>,
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
            blacklist_manager,
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

    pub async fn start_capture(
        &mut self,
        target_interfaces: Option<String>,
        _filter: Option<String>,
    ) -> Result<()> {
        let interfaces = if let Some(targets) = target_interfaces {
            targets
                .split(',')
                .map(|s: &str| s.trim().to_string())
                .collect::<Vec<_>>()
        } else {
            error!("XDP mode requires specific interfaces. 'any' is not supported.");
            return Err(anyhow::anyhow!("Target interface required for XDP"));
        };

        let save_root = self.save_root_dir.clone();
        let interval_secs = self.interval;
        let my_ips = self.my_ip_set.clone();
        let log_period = self.log_period;
        let pcap_period = self.pcap_period;
        let suricata_ref = self.suricata_processor.clone();
        let filter_opt = _filter.clone();
        let blacklist_manager_ref = self.blacklist_manager.clone();

        // XDP 캡처 태스크 시작
        for iface in interfaces {
            let save_root_clone = save_root.clone();
            let my_ips_clone = my_ips.clone();
            let suricata_clone = suricata_ref.clone();
            let iface_clone = iface.clone();
            let filter_clone = filter_opt.clone();
            let blacklist_manager_clone = blacklist_manager_ref.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::capture_and_save_loop_xdp(
                    &iface_clone,
                    &save_root_clone,
                    interval_secs,
                    my_ips_clone,
                    suricata_clone,
                    filter_clone,
                    blacklist_manager_clone,
                )
                .await
                {
                    error!("XDP Capture error on {}: {}", iface_clone, e);
                }
            });
        }

        // 파일 정리 스케줄러
        let save_root_cleanup = save_root.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // 1시간마다
            loop {
                interval.tick().await;
                if let Err(e) =
                    Self::file_organizer_static(&save_root_cleanup, log_period, pcap_period)
                {
                    error!("File organizer error: {}", e);
                }
            }
        });

        Ok(())
    }

    async fn capture_and_save_loop_xdp(
        interface: &str,
        save_root: &str,
        interval_secs: u64,
        my_ips: HashSet<String>,
        suricata: Arc<Mutex<SuricataPcapProcessor>>,
        filter: Option<String>,
        blacklist_manager: Option<Arc<BlacklistManager>>,
    ) -> Result<()> {
        info!("Starting XDP capture on interface: {}", interface);

        let mut bpf_path = PathBuf::from("target/bpfel-unknown-none/debug/ids-xdp");
        if !bpf_path.exists() {
            bpf_path = PathBuf::from("target/bpfel-unknown-none/release/ids-xdp");
            if !bpf_path.exists() {
                return Err(anyhow::anyhow!(
                    "eBPF binary not found at {:?}. Please build it first with `cargo build --package ids-xdp`.",
                    bpf_path
                ));
            }
        }
        info!("Loading eBPF from {:?}", bpf_path);

        let mut bpf = Ebpf::load_file(&bpf_path)?;
        let program: &mut Xdp = bpf.program_mut("xdp_ids").unwrap().try_into()?;
        program.load()?;
        program
            .attach(interface, XdpFlags::default())
            .context(format!("Failed to attach XDP to {}", interface))?;

        let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

        // (data, timestamp, original_len)
        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, i64, u32)>(5000);

        let cpus =
            online_cpus().map_err(|e| anyhow::anyhow!("Failed to get online cpus: {:?}", e))?;
        for cpu_id in cpus {
            let mut buf = perf_array.open(cpu_id, None)?;
            let tx = tx.clone();

            tokio::spawn(async move {
                // 패킷 최대 크기(65535) + 이벤트 구조체 크기 등을 고려하여 버퍼 크기 넉넉하게 잡음
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(65536 + 1024))
                    .collect::<Vec<_>>();

                loop {
                    let events = buf.read_events(&mut buffers).await;
                    match events {
                        Ok(events) => {
                            for i in 0..events.read {
                                let buf = &buffers[i];

                                // PacketEvent 구조체 읽기
                                let event_size = std::mem::size_of::<PacketEvent>();
                                if buf.len() < event_size {
                                    continue;
                                }

                                let event = unsafe {
                                    let ptr = buf.as_ptr() as *const PacketEvent;
                                    *ptr
                                };

                                let packet_len = event.len as usize;

                                // 실제 패킷 데이터는 구조체 바로 뒤에 위치
                                if buf.len() < event_size + packet_len {
                                    // 버퍼가 잘린 경우 (should not happen with sufficient buffer size)
                                    continue;
                                }

                                let data = buf[event_size..event_size + packet_len].to_vec();

                                let ts = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_nanos() as i64;

                                if tx.send((data, ts, event.len)).await.is_err() {
                                    return;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        let linktype = Linktype::ETHERNET;

        loop {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let buffer_time = current_time - (current_time % interval_secs as i64);
            let next_buffer_time = buffer_time + interval_secs as i64;

            let temp_pcap_path = format!("{}/temp_pcap/{}.pcap", save_root, buffer_time);

            // pcap 파일 생성
            let cap = Capture::dead(linktype)?;
            let mut savefile = cap.savefile(&temp_pcap_path)?;

            let mut packet_stats: HashMap<String, PacketStat> = HashMap::new();
            let mut packet_count = 0u64;

            info!(
                "Creating pcap file for buffer time {}: {}",
                buffer_time, temp_pcap_path
            );

            loop {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                if now >= next_buffer_time {
                    break;
                }

                let remaining = next_buffer_time - now;
                let timeout_duration =
                    Duration::from_secs(if remaining > 0 { remaining as u64 } else { 1 });

                match tokio::time::timeout(timeout_duration, rx.recv()).await {
                    Ok(Some((data, ts, orig_len))) => {
                        let header = PacketHeader {
                            ts: libc::timeval {
                                tv_sec: (ts / 1_000_000_000) as libc::time_t,
                                tv_usec: ((ts % 1_000_000_000) / 1000) as libc::suseconds_t,
                            },
                            caplen: data.len() as u32,
                            len: orig_len,
                        };

                        let packet = Packet {
                            header: &header,
                            data: &data,
                        };
                        savefile.write(&packet);

                        packet_count += 1;

                        Self::process_packet_stats(&data, ts, &my_ips, &mut packet_stats);
                    }
                    Ok(None) => return Ok(()),
                    Err(_) => continue,
                }
            }

            drop(savefile);
            info!(
                "Buffer {} completed: {} packets captured",
                buffer_time, packet_count
            );

            let save_root_clone = save_root.to_string();
            let suricata_clone = suricata.clone();
            let temp_path = temp_pcap_path.clone();
            let blacklist_manager_clone = blacklist_manager.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::process_completed_buffer(
                    buffer_time,
                    &save_root_clone,
                    &temp_path,
                    packet_stats,
                    suricata_clone,
                    blacklist_manager_clone,
                ) {
                    error!("Buffer processing error: {}", e);
                }
            });
        }
    }

    fn process_packet_stats(
        data: &[u8],
        timestamp_ns: i64,
        my_ips: &HashSet<String>,
        stats: &mut HashMap<String, PacketStat>,
    ) {
        // Ethernet 패킷 파싱
        let ip_data = if let Some(eth) = EthernetPacket::new(data) {
            if eth.get_ethertype() == EtherTypes::Ipv4 {
                Some(eth.payload().to_vec())
            } else {
                None
            }
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
        mut packet_stats: HashMap<String, PacketStat>,
        suricata: Arc<Mutex<SuricataPcapProcessor>>,
        blacklist_manager: Option<Arc<BlacklistManager>>,
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

        // pcap 파일 이동
        let new_pcap_path = format!("{}/{}.pcap", save_pcap_dir, save_file_name);
        if Path::new(temp_pcap_path).exists() {
            fs::rename(temp_pcap_path, &new_pcap_path)?;
            info!("Saved pcap: {}", new_pcap_path);
        } else {
            warn!("Temp pcap file not found: {}", temp_pcap_path);
        }

        // Suricata 분석 수행
        let pcap_absolute_path = fs::canonicalize(&new_pcap_path)
            .unwrap_or_else(|_| PathBuf::from(&new_pcap_path))
            .to_string_lossy()
            .to_string();

        let pcap_info = PcapProcessingInfo::new(
            save_log_dir.clone(),
            save_pcap_dir.clone(),
            save_file_name.clone(),
            pcap_absolute_path,
            packet_stats.clone(),
        );

        match suricata.lock().unwrap().process_pcap(&pcap_info) {
            Ok(records) => {
                for record in records {
                    Self::merge_suricata_record(&mut packet_stats, &record);
                }
                info!("Suricata analysis merged. Records: {}", packet_stats.len());
            }
            Err(e) => error!("Suricata processing failed: {}", e),
        }

        // 블랙리스트 검사
        if let Some(bm) = blacklist_manager {
            let blacklists = bm.get_blacklists();
            for stat in packet_stats.values_mut() {
                for (list_name, ip_set) in blacklists {
                    if ip_set.contains(&stat.src_ip) || ip_set.contains(&stat.dst_ip) {
                        stat.blacklist.push(list_name.clone());
                    }
                }
            }
        }

        // 로그 파일 저장
        let log_path = format!("{}/{}.log", save_log_dir, save_file_name);
        let mut log_file = File::create(&log_path)?;

        writeln!(log_file, "{}", PacketStat::log_header())?;
        for stat in packet_stats.values() {
            writeln!(log_file, "{}", stat.print())?;
        }

        info!("Saved log: {} ({} flows)", log_path, packet_stats.len());

        Ok(())
    }

    fn merge_suricata_record(stats: &mut HashMap<String, PacketStat>, record: &serde_json::Value) {
        let src_ip = record["srcIp"].as_str().unwrap_or_default();
        let dst_ip = record["dstIp"].as_str().unwrap_or_default();
        let src_port = record["srcPort"].as_u64().unwrap_or_default() as u16;
        let dst_port = record["dstPort"].as_u64().unwrap_or_default() as u16;

        let key1 = format!("{}:{}-{}:{}", src_ip, src_port, dst_ip, dst_port);
        let key2 = format!("{}:{}-{}:{}", dst_ip, dst_port, src_ip, src_port);

        let stat_opt: Option<&mut PacketStat> = if stats.contains_key(&key1) {
            stats.get_mut(&key1)
        } else if stats.contains_key(&key2) {
            stats.get_mut(&key2)
        } else {
            None
        };

        if let Some(stat) = stat_opt {
            if let Some(val) = record["appProto"].as_str() {
                if stat.app_proto == "Unknown" && val != "failed" {
                    stat.app_proto = val.to_string();
                }
            }

            if let Some(val) = record["alertSubLabel"].as_u64() {
                stat.sub_label = val as u32;
            }

            if let Some(val) = record["alertXid"].as_u64() {
                stat.xid = val as u32;
            }

            if let Some(val) = record["eventType"].as_str(){
                stat.suricata_event_type = val.to_string();
            }

            if let Some(val) = record["mal"].as_u64() {
                stat.mal = val as u32;
            }
            if let Some(val) = record["flowId"].as_u64() {
                stat.flow_id = val.to_string();
            }
        }
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
                        let depth =
                            path.components().count() - Path::new(base_path).components().count();

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
