use anyhow::{Context, Result};
use chrono::{DateTime, FixedOffset};
use log::{debug, error, info, warn};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

use crate::config::SuricataConfig;
use crate::dto::{PacketStat, PcapProcessingInfo};

const PID_FILE: &str = "/var/run/suricata.pid";

pub struct SuricataProcessManager {
    config: SuricataConfig,
    process: Option<Child>,
    running: Arc<Mutex<bool>>,
    pcap_process_queue: Arc<Mutex<HashMap<String, bool>>>,
    pcap_eve_log_complete_time: Arc<Mutex<HashMap<u64, bool>>>,
}

impl SuricataProcessManager {
    pub fn new(config: SuricataConfig) -> Self {
        Self {
            config,
            process: None,
            running: Arc::new(Mutex::new(false)),
            pcap_process_queue: Arc::new(Mutex::new(HashMap::new())),
            pcap_eve_log_complete_time: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn check_existing(&self) -> Option<u32> {
        if Path::new(PID_FILE).exists() {
            if let Ok(pid_str) = fs::read_to_string(PID_FILE) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    return Some(pid);
                }
            }
        }
        None
    }

    fn cleanup_existing(&self) -> Result<()> {
        if let Some(pid) = self.check_existing() {
            info!("Found existing Suricata process (PID: {}), stopping...", pid);

            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;

                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                thread::sleep(Duration::from_secs(3));
            }

            let _ = fs::remove_file(PID_FILE);
        }

        if Path::new(&self.config.socket_path).exists() {
            fs::remove_file(&self.config.socket_path)?;
            info!("Removed existing socket: {}", self.config.socket_path);
        }

        Ok(())
    }

    pub fn start(&mut self) -> Result<()> {
        self.cleanup_existing()?;

        let socket_dir = Path::new(&self.config.socket_path)
            .parent()
            .context("Invalid socket path")?;
        fs::create_dir_all(socket_dir)?;

        let cmd = format!(
            "suricata -c {} --unix-socket --pidfile={} -vvv",
            self.config.config_file_path, PID_FILE
        );

        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start Suricata")?;

        let stdout = child.stdout.take().context("Failed to capture stdout")?;
        let running = self.running.clone();
        let pcap_queue = self.pcap_process_queue.clone();
        let eve_complete = self.pcap_eve_log_complete_time.clone();

        thread::spawn(move || {
            Self::output_process(stdout, running, pcap_queue, eve_complete);
        });

        info!("Suricata started in Unix socket mode");

        for _ in 0..30 {
            if Path::new(&self.config.socket_path).exists() {
                info!("Suricata socket ready at {}", self.config.socket_path);
                self.process = Some(child);
                return Ok(());
            }
            thread::sleep(Duration::from_secs(1));
        }

        error!("Suricata socket not created within timeout");
        anyhow::bail!("Suricata socket timeout")
    }

    fn output_process(
        stdout: std::process::ChildStdout,
        running: Arc<Mutex<bool>>,
        pcap_queue: Arc<Mutex<HashMap<String, bool>>>,
        eve_complete: Arc<Mutex<HashMap<u64, bool>>>,
    ) {
        let reader = BufReader::new(stdout);

        let load_complete_pattern = Regex::new(r"^.+Engine\s+started.$").unwrap();
        let pcap_add_pattern = Regex::new(r"^.+unix-socket: Added file\s+'(.+)'.+to list$").unwrap();
        let pcap_start_pattern = Regex::new(r"^.+unix-socket: Starting run for\s+'(.+)'$").unwrap();
        let pcap_complete_pattern = Regex::new(r"^.+pcap: pcap file\s+(.+)\s+end of file reached\s+.+$").unwrap();
        let eve_log_complete_pattern = Regex::new(r"^.+Info: counters:.+$").unwrap();

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };

            let trimmed = line.trim();
            debug!("SURICATA OUTPUT: {}", trimmed);

            if load_complete_pattern.is_match(trimmed) {
                info!("SURICATA Load Complete.");
                *running.lock().unwrap() = true;
                continue;
            }

            if let Some(caps) = pcap_add_pattern.captures(trimmed) {
                let path = caps.get(1).unwrap().as_str().to_string();
                info!("PCAP_ADD_FIND: {}", trimmed);
                pcap_queue.lock().unwrap().insert(path, false);
                continue;
            }

            if let Some(_caps) = pcap_start_pattern.captures(trimmed) {
                info!("PCAP_START_FIND: {}", trimmed);
                continue;
            }

            if let Some(caps) = pcap_complete_pattern.captures(trimmed) {
                let path = caps.get(1).unwrap().as_str().to_string();
                info!("PCAP_COMPLETE_FIND: {}", trimmed);
                pcap_queue.lock().unwrap().insert(path, true);
                continue;
            }

            if eve_log_complete_pattern.is_match(trimmed) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                eve_complete.lock().unwrap().insert(now, true);
                continue;
            }
        }

        error!("SURICATA PROCESS CLOSED");
    }

    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }

    pub fn wait_pcap_complete(&self, pcap_path: &str) -> Result<()> {
        info!("Waiting for pcap processing: {}", pcap_path);

        loop {
            {
                let queue = self.pcap_process_queue.lock().unwrap();
                if let Some(&completed) = queue.get(pcap_path) {
                    if completed {
                        info!("PCAP processing completed: {}", pcap_path);
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(100));
        }

        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        loop {
            {
                let complete_times = self.pcap_eve_log_complete_time.lock().unwrap();
                for &time in complete_times.keys() {
                    if time >= start_time {
                        info!("EVE log writing completed");
                        return Ok(());
                    }
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn stop(&mut self) -> Result<()> {
        *self.running.lock().unwrap() = false;

        if let Some(mut child) = self.process.take() {
            child.kill()?;
            child.wait()?;
        }

        let _ = fs::remove_file(PID_FILE);
        let _ = fs::remove_file(&self.config.socket_path);

        info!("Suricata stopped");
        Ok(())
    }
}

pub struct SuricataCommandExecutor {
    socket_path: String,
}

impl SuricataCommandExecutor {
    pub fn new(socket_path: String) -> Self {
        Self { socket_path }
    }

    pub fn send_command(&self, command: &str) -> Result<Value> {
        info!("Input Command: {}", command);
        let suricata_command = format!("/bin/suricatasc -c \"{}\"", command);
        info!("EXEC suricata Command: {}", suricata_command);

        let output = Command::new("sh")
            .arg("-c")
            .arg(&suricata_command)
            .output()
            .context("Failed to execute suricatasc")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        info!("Result: {}", stdout);
        if !stderr.is_empty() {
            warn!("Error output: {}", stderr);
        }

        if !output.status.success() {
            error!("Command failed with return code {:?}", output.status.code());
        }

        let result: Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|_| json!({}));

        Ok(result)
    }

    pub fn process_pcap(&self, pcap_path: &str, output_dir: &str) -> Result<bool> {
        let path = Path::new(pcap_path);
        if !path.exists() {
            error!("PCAP file not found: {}", pcap_path);
            return Ok(false);
        }

        let pcap_absolute = path.canonicalize()?;
        let command = format!(
            "pcap-file {} {} 1 true",
            pcap_absolute.display(),
            output_dir
        );

        let response = self.send_command(&command)?;

        if response.get("return").and_then(|v| v.as_str()) == Some("OK") {
            info!("Successfully queued PCAP: {}", pcap_path);
            Ok(true)
        } else {
            error!("Failed to process PCAP: {}", pcap_path);
            if let Some(msg) = response.get("message") {
                error!("Error response: {}", msg);
            }
            Ok(false)
        }
    }

    pub fn get_version(&self) -> Result<Value> {
        self.send_command("version")
    }
}

pub struct EVELogParser {
    xid_map: HashMap<String, u32>,
    sub_label_map: HashMap<u32, u32>,
    rule_xid_dict: HashMap<u32, u32>,
    rule_sub_label_dict: HashMap<u32, u32>,
    suricata_classification: HashMap<String, String>,
}

impl EVELogParser {
    pub fn new() -> Self {
        let mut xid_map = HashMap::new();
        xid_map.insert("domain-c2".to_string(), 2);
        xid_map.insert("command-and-control".to_string(), 2);
        xid_map.insert("targeted-activity".to_string(), 2);
        xid_map.insert("coin-mining".to_string(), 2);
        xid_map.insert("exploit-kit".to_string(), 2);
        xid_map.insert("attempted-dos".to_string(), 4);
        xid_map.insert("successful-dos".to_string(), 5);
        xid_map.insert("denial-of-service".to_string(), 5);
        xid_map.insert("network-scan".to_string(), 6);
        xid_map.insert("attempted-admin".to_string(), 7);
        xid_map.insert("attempted-user".to_string(), 7);
        xid_map.insert("unsuccessful-user".to_string(), 7);
        xid_map.insert("default-login-attempt".to_string(), 11);
        xid_map.insert("successful-admin".to_string(), 8);
        xid_map.insert("successful-user".to_string(), 8);
        xid_map.insert("attempted-recon".to_string(), 9);
        xid_map.insert("external-ip-check".to_string(), 9);
        xid_map.insert("successful-recon-limited".to_string(), 10);
        xid_map.insert("successful-recon-largescale".to_string(), 10);
        xid_map.insert("suspicious-login".to_string(), 11);
        xid_map.insert("credential-theft".to_string(), 11);
        xid_map.insert("trojan-activity".to_string(), 16);
        xid_map.insert("pup-activity".to_string(), 16);
        xid_map.insert("social-engineering".to_string(), 16);
        xid_map.insert("rpc-portmap-decode".to_string(), 16);
        xid_map.insert("unusual-client-port-connection".to_string(), 16);
        xid_map.insert("non-standard-protocol".to_string(), 16);
        xid_map.insert("web-application-activity".to_string(), 17);
        xid_map.insert("web-application-attack".to_string(), 18);
        xid_map.insert("protocol-command-decode".to_string(), 19);
        xid_map.insert("shellcode-detect".to_string(), 19);
        xid_map.insert("system-call-detect".to_string(), 19);
        xid_map.insert("suspicious-filename-detect".to_string(), 20);
        xid_map.insert("misc-activity".to_string(), 99);
        xid_map.insert("bad-unknown".to_string(), 99);
        xid_map.insert("policy-violation".to_string(), 99);
        xid_map.insert("unknown".to_string(), 99);
        xid_map.insert("misc-attack".to_string(), 99);
        xid_map.insert("not-suspicious".to_string(), 99);
        xid_map.insert("string-detect".to_string(), 99);

        let mut sub_label_map = HashMap::new();
        sub_label_map.insert(2, 1);
        sub_label_map.insert(4, 2);
        sub_label_map.insert(5, 3);
        sub_label_map.insert(6, 4);
        sub_label_map.insert(7, 5);
        sub_label_map.insert(8, 6);
        sub_label_map.insert(9, 7);
        sub_label_map.insert(10, 8);
        sub_label_map.insert(11, 9);
        sub_label_map.insert(16, 10);
        sub_label_map.insert(17, 11);
        sub_label_map.insert(18, 12);
        sub_label_map.insert(19, 13);
        sub_label_map.insert(20, 14);
        sub_label_map.insert(99, 99);

        Self {
            xid_map,
            sub_label_map,
            rule_xid_dict: HashMap::new(),
            rule_sub_label_dict: HashMap::new(),
            suricata_classification: HashMap::new(),
        }
    }

    pub fn rule_parse(&mut self, rule_dir: &str, rule_file_name_list: &[String]) {
        let classification_config = format!("{}/classification.config", rule_dir);
        let classification_pattern = Regex::new(r"config classification:\s+(.+),(.+),(\d+)").unwrap();

        if let Ok(file) = File::open(&classification_config) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                let line = line.trim();
                if let Some(caps) = classification_pattern.captures(line) {
                    let key = caps.get(2).unwrap().as_str().trim().to_string();
                    let value = caps.get(1).unwrap().as_str().trim().to_string();
                    self.suricata_classification.insert(key, value);
                }
            }
        } else {
            error!("Failed to open classification config: {}", classification_config);
        }

        let rule_detail_pattern = Regex::new(r"\((.+)\)").unwrap();

        for rule_file_name in rule_file_name_list {
            let rule_path = format!("{}/{}", rule_dir, rule_file_name);
            if let Ok(file) = File::open(&rule_path) {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten() {
                    let line = line.trim();
                    if let Some(caps) = rule_detail_pattern.captures(line) {
                        let rule_detail = caps.get(1).unwrap().as_str();
                        let entities: Vec<&str> = rule_detail.split(';').collect();
                        
                        let mut rule_dict = HashMap::new();
                        for entity in entities {
                            let parts: Vec<&str> = entity.split(':').collect();
                            if parts.len() == 2 {
                                rule_dict.insert(parts[0].trim(), parts[1].trim());
                            }
                        }

                        if let (Some(sid_str), Some(classtype)) = (rule_dict.get("sid"), rule_dict.get("classtype")) {
                            if let Ok(sid) = sid_str.parse::<u32>() {
                                if let Some(xid) = self.xid_map.get(*classtype) {
                                    self.rule_xid_dict.insert(sid, *xid);
                                    if let Some(sub_label) = self.sub_label_map.get(xid) {
                                        self.rule_sub_label_dict.insert(sid, *sub_label);
                                    } else {
                                        self.rule_sub_label_dict.insert(sid, 99);
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                error!("Failed to open rule file: {}", rule_path);
            }
        }
        info!("Rule parsing complete. Loaded {} rules.", self.rule_xid_dict.len());
    }

    pub fn parse_eve_log(&self, log_path: &str) -> Result<Vec<Value>> {
        info!("Parsing Suricata log file: {}", log_path);
        let mut records = Vec::new();

        let file = File::open(log_path)
            .with_context(|| format!("Failed to open eve log: {}", log_path))?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<Value>(&line) {
                Ok(data) => {
                    if let Some(processed) = self.process_eve_record(&data) {
                        records.push(processed);
                    }
                }
                Err(e) => {
                    error!("Failed to parse JSON line: {} - Error: {}", line, e);
                }
            }
        }

        Ok(records)
    }

    fn parse_tcp_flags(&self, flags_string: &str) -> HashMap<char, i32> {
        let mut counts = HashMap::new();
        for c in flags_string.chars() {
            *counts.entry(c).or_insert(0) += 1;
        }
        counts
    }

    fn convert_timestamp(&self, timestamp_str: &str) -> Option<i64> {
        match DateTime::parse_from_rfc3339(timestamp_str) {
            Ok(dt) => Some(dt.timestamp_nanos_opt().unwrap_or(0)),
            Err(_) => None,
        }
    }

    fn process_eve_record(&self, data: &Value) -> Option<Value> {
        let event_type = data.get("event_type")?.as_str()?;

        let mut record = json!({
            "flowId": data.get("flow_id"),
            "mal": 0,
            "eventType": event_type,
        });

        if !matches!(event_type, "flow" | "http" | "tls" | "ssh" | "quic" | "alert" | "anomaly") {
            return None;
        }

        let record_obj = record.as_object_mut().unwrap();
        let flow = data.get("flow");

        // 기본 정보 및 통계
        if event_type == "flow" || flow.is_some() {
            if let Some(flow_obj) = flow {
                if let Some(start_str) = flow_obj.get("start").and_then(|v| v.as_str()) {
                    if let Some(ts) = self.convert_timestamp(start_str) {
                        record_obj.insert("firstSeenMs".to_string(), json!(ts));
                    }
                }
                if let Some(end_str) = flow_obj.get("end").and_then(|v| v.as_str()) {
                    if let Some(ts) = self.convert_timestamp(end_str) {
                        record_obj.insert("lastSeenMs".to_string(), json!(ts));
                    }
                }

                record_obj.insert("appProto".to_string(), data.get("proto").unwrap_or(&json!("Unknown")).clone());
                record_obj.insert("masterProto".to_string(), data.get("app_proto").unwrap_or(&json!("Unknown")).clone());
                record_obj.insert("l4Proto".to_string(), json!("Unknown")); // Python matches logic: fixed to Unknown
                
                let src_ip = data.get("src_ip").unwrap_or(&json!("")).as_str().unwrap_or("").to_string();
                let src_port = data.get("src_port").unwrap_or(&json!(0)).to_string();
                let dst_ip = data.get("dest_ip").unwrap_or(&json!("")).as_str().unwrap_or("").to_string();
                let dst_port = data.get("dest_port").unwrap_or(&json!(0)).to_string();

                record_obj.insert("srcIp".to_string(), json!(src_ip));
                record_obj.insert("srcPort".to_string(), data.get("src_port").unwrap_or(&json!(0)).clone());
                record_obj.insert("dstIp".to_string(), json!(dst_ip));
                record_obj.insert("dstPort".to_string(), data.get("dest_port").unwrap_or(&json!(0)).clone());
                
                record_obj.insert("srcIp:port".to_string(), json!(format!("{}:{}", src_ip, src_port)));
                record_obj.insert("dstIp:port".to_string(), json!(format!("{}:{}", dst_ip, dst_port)));

                let s2d_pkts = flow_obj.get("pkts_toserver").and_then(|v| v.as_u64()).unwrap_or(0);
                let d2s_pkts = flow_obj.get("pkts_toclient").and_then(|v| v.as_u64()).unwrap_or(0);
                let s2d_bytes = flow_obj.get("bytes_toserver").and_then(|v| v.as_u64()).unwrap_or(0);
                let d2s_bytes = flow_obj.get("bytes_toclient").and_then(|v| v.as_u64()).unwrap_or(0);

                record_obj.insert("totalPackets".to_string(), json!(s2d_pkts + d2s_pkts));
                record_obj.insert("totalBytes".to_string(), json!(s2d_bytes + d2s_bytes));
                record_obj.insert("s2dPackets".to_string(), json!(s2d_pkts));
                record_obj.insert("s2dBytes".to_string(), json!(s2d_bytes));
                record_obj.insert("d2sPackets".to_string(), json!(d2s_pkts));
                record_obj.insert("d2sBytes".to_string(), json!(d2s_bytes));

                if s2d_bytes > 0 && d2s_bytes > 0 {
                    record_obj.insert("dataRatio".to_string(), json!((s2d_bytes as f64) / (d2s_bytes as f64)));
                }

                if data.get("proto").and_then(|v| v.as_str()) == Some("TCP") {
                    let s2d_flags_str = flow_obj.get("tcp_flags_ts").and_then(|v| v.as_str()).unwrap_or("");
                    let d2s_flags_str = flow_obj.get("tcp_flags_tc").and_then(|v| v.as_str()).unwrap_or("");
                    
                    let s2d_counts = self.parse_tcp_flags(s2d_flags_str);
                    let d2s_counts = self.parse_tcp_flags(d2s_flags_str);

                    let flags_map = [
                        ('C', "cwr"), ('E', "ece"), ('U', "urg"), ('A', "ack"), 
                        ('P', "psh"), ('R', "rst"), ('S', "syn"), ('F', "fin")
                    ];

                    for (char_code, name) in flags_map {
                        let s2d_c = *s2d_counts.get(&char_code).unwrap_or(&0);
                        let d2s_c = *d2s_counts.get(&char_code).unwrap_or(&0);
                        let total_c = s2d_c + d2s_c;

                        let mut name_cap = name.to_string(); // capitalize manually if needed, but python logic uses `name.capitalize()`
                        // Python: cwr -> Cwr
                        if let Some(first) = name_cap.get_mut(0..1) {
                            first.make_ascii_uppercase();
                        }

                        record_obj.insert(format!("s2d{}Count", name_cap), json!(s2d_c));
                        record_obj.insert(format!("d2s{}Count", name_cap), json!(d2s_c));
                        record_obj.insert(format!("{}Count", name), json!(total_c));
                    }
                }
            }
        }

        if event_type != "alert" && event_type != "anomaly" && event_type != "flow" {
            record_obj.insert("eventType".to_string(), json!(event_type));
        }

        // 응용 계층 정보
        let http = data.get("http");
        if event_type == "http" || http.is_some() {
            if let Some(http_obj) = http {
                record_obj.insert("httpUrl".to_string(), http_obj.get("url").unwrap_or(&json!("")).clone());
                record_obj.insert("hostServerName".to_string(), http_obj.get("hostname").unwrap_or(&json!("")).clone());
                
                let user_agent = http_obj.get("http_user_agent").and_then(|v| v.as_str()).unwrap_or("");
                record_obj.insert("userAgent".to_string(), json!(user_agent));
                
                record_obj.insert("httpResponseStatusCode".to_string(), http_obj.get("status").unwrap_or(&json!("")).clone());
                record_obj.insert("httpLength".to_string(), http_obj.get("length").unwrap_or(&json!("")).clone());

                if !user_agent.is_empty() {
                    let ua_lower = user_agent.to_lowercase();
                    record_obj.insert("isSafari".to_string(), json!(ua_lower.contains("safari") && !ua_lower.contains("chrome")));
                    record_obj.insert("isChrome".to_string(), json!(ua_lower.contains("chrome") && ua_lower.contains("safari"))); // Note: Chrome UA usually has both
                    record_obj.insert("isFirefox".to_string(), json!(ua_lower.contains("firefox")));
                }
            }
        }

        let tls = data.get("tls");
        if event_type == "tls" || tls.is_some() {
            if let Some(tls_obj) = tls {
                record_obj.insert("tls/sslServerNames".to_string(), tls_obj.get("sni").unwrap_or(&json!("")).clone());
                record_obj.insert("subjectDn".to_string(), tls_obj.get("subject").unwrap_or(&json!("")).clone());
                record_obj.insert("issuerDn".to_string(), tls_obj.get("issuerdn").unwrap_or(&json!("")).clone());
                record_obj.insert("tls/sslVersion".to_string(), tls_obj.get("version").unwrap_or(&json!("")).clone());
                record_obj.insert("certificateSha1".to_string(), tls_obj.get("fingerprint").unwrap_or(&json!("")).clone());
                
                if let Some(ja3) = data.get("ja3") {
                    record_obj.insert("ja3ClientHash".to_string(), ja3.get("hash").unwrap_or(&json!("")).clone());
                }
                if let Some(ja3s) = data.get("ja3s") {
                    record_obj.insert("ja3ServerHash".to_string(), ja3s.get("hash").unwrap_or(&json!("")).clone());
                }
                if let Some(ja4) = data.get("ja4") {
                    record_obj.insert("ja4Client".to_string(), ja4.get("hash").unwrap_or(&json!("")).clone());
                }
            }
        }

        let ssh = data.get("ssh");
        if event_type == "ssh" || ssh.is_some() {
            if let Some(ssh_obj) = ssh {
                if let Some(client) = ssh_obj.get("client") {
                    record_obj.insert("clientHassh".to_string(), client.get("hassh").unwrap_or(&json!("")).clone());
                }
                if let Some(server) = ssh_obj.get("server") {
                    record_obj.insert("serverHassh".to_string(), server.get("hassh").unwrap_or(&json!("")).clone());
                }
            }
        }

        if event_type == "quic" {
            if let Some(quic) = data.get("quic") {
                record_obj.insert("quicVersion".to_string(), quic.get("version").unwrap_or(&json!("")).clone());
            }
        }

        let alert = data.get("alert");
        if event_type == "alert" || alert.is_some() {
            if let Some(alert_obj) = alert {
                let sid = alert_obj.get("signature_id").and_then(|v| v.as_u64()).unwrap_or(0);
                
                // Rust version note: rule_xid_dict is currently empty as rule parsing is not fully ported.
                // Assuming defaults if not found.
                let alert_xid = self.rule_xid_dict.get(&(sid as u32)).cloned().unwrap_or(99);
                let alert_sub_label = self.rule_sub_label_dict.get(&(sid as u32)).cloned().unwrap_or(99);

                record_obj.insert("alertId".to_string(), json!(sid));
                record_obj.insert("alertSubLabel".to_string(), json!(alert_sub_label));
                record_obj.insert("alertXid".to_string(), json!(alert_xid));
                record_obj.insert("alertName".to_string(), alert_obj.get("signature").unwrap_or(&json!("")).clone());
                record_obj.insert("alertCategory".to_string(), alert_obj.get("category").unwrap_or(&json!("")).clone());
                record_obj.insert("mal".to_string(), json!(1));
            }
        }

        let anomaly = data.get("anomaly");
        if event_type == "anomaly" || anomaly.is_some() {
            if let Some(anomaly_obj) = anomaly {
                record_obj.insert("appProto".to_string(), anomaly_obj.get("app_proto").unwrap_or(&json!("")).clone());
                record_obj.insert("anomalyType".to_string(), anomaly_obj.get("type").unwrap_or(&json!("")).clone());
                record_obj.insert("anomalyEvent".to_string(), anomaly_obj.get("event").unwrap_or(&json!("")).clone());
                record_obj.insert("anomalyLayer".to_string(), anomaly_obj.get("layer").unwrap_or(&json!("")).clone());
            }
        }

        // 공통 사항
        record_obj.insert("plainText".to_string(), data.get("payload_printable").unwrap_or(&json!("")).clone());
        record_obj.insert("payload".to_string(), data.get("payload").unwrap_or(&json!("")).clone());

        Some(record)
    }
}

pub struct SuricataPcapProcessor {
    config: SuricataConfig,
    process_manager: Option<SuricataProcessManager>,
    cmd_executor: SuricataCommandExecutor,
    eve_parser: EVELogParser,
}

impl SuricataPcapProcessor {
    pub fn new(config: SuricataConfig) -> Self {
        let cmd_executor = SuricataCommandExecutor::new(config.socket_path.clone());
        let eve_parser = EVELogParser::new();

        Self {
            config: config.clone(),
            process_manager: Some(SuricataProcessManager::new(config)),
            cmd_executor,
            eve_parser,
        }
    }

    pub fn start(&mut self) -> Result<()> {
        if let Some(manager) = &mut self.process_manager {
            manager.start()?;

            while !manager.is_running() {
                info!("Waiting for suricata to load...");
                thread::sleep(Duration::from_secs(1));
            }
            info!("Suricata load complete!");

            thread::sleep(Duration::from_secs(5));

            let version = self.cmd_executor.get_version()?;
            if version.get("return").and_then(|v| v.as_str()) == Some("OK") {
                info!("Connected to Suricata: {:?}", version.get("message"));
            }

            self.eve_parser.rule_parse(&self.config.rule_dir, &self.config.rule_file_name_list);
        }

        Ok(())
    }

    pub fn process_pcap(&self, pcap_info: &PcapProcessingInfo) -> Result<Vec<Value>> {
        let current_log_dir = format!("{}/{}", self.config.log_dir, pcap_info.save_file_name);
        info!("Suricata Log Target Path: {}", current_log_dir);
        fs::create_dir_all(&current_log_dir)?;

        if pcap_info.packet_stats_dict.is_empty() {
            info!("No packets to process");
            return Ok(Vec::new());
        }

        self.cmd_executor.process_pcap(
            &pcap_info.read_pcap_file_absolute_path,
            &current_log_dir,
        )?;

        if let Some(manager) = &self.process_manager {
            manager.wait_pcap_complete(&pcap_info.read_pcap_file_absolute_path)?;
        }

        let eve_log_path = format!("{}/eve.json", current_log_dir);
        let records = self.eve_parser.parse_eve_log(&eve_log_path)?;
        
        Ok(records)
    }

    pub fn stop(&mut self) -> Result<()> {
        if let Some(manager) = &mut self.process_manager {
            manager.stop()?;
        }
        Ok(())
    }
}
