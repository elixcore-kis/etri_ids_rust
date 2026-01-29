use anyhow::{Context, Result};
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

        Self {
            xid_map,
            sub_label_map,
            rule_xid_dict: HashMap::new(),
            rule_sub_label_dict: HashMap::new(),
        }
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

    fn process_eve_record(&self, data: &Value) -> Option<Value> {
        let event_type = data.get("event_type")?.as_str()?;

        if !matches!(event_type, "flow" | "http" | "tls" | "ssh" | "quic" | "alert" | "anomaly") {
            return None;
        }

        let mut record = json!({
            "flowId": data.get("flow_id"),
            "mal": 0,
        });

        if let Some(_flow) = data.get("flow") {
            if let Some(obj) = record.as_object_mut() {
                obj.insert("appProto".to_string(), data.get("proto").unwrap_or(&json!("Unknown")).clone());
                obj.insert("masterProto".to_string(), data.get("app_proto").unwrap_or(&json!("Unknown")).clone());
                obj.insert("srcIp".to_string(), data.get("src_ip").unwrap_or(&json!("")).clone());
                obj.insert("srcPort".to_string(), data.get("src_port").unwrap_or(&json!(0)).clone());
                obj.insert("dstIp".to_string(), data.get("dest_ip").unwrap_or(&json!("")).clone());
                obj.insert("dstPort".to_string(), data.get("dest_port").unwrap_or(&json!(0)).clone());
            }
        }

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
        }

        Ok(())
    }

    pub fn process_pcap(&self, pcap_info: &PcapProcessingInfo) -> Result<()> {
        let current_log_dir = format!("{}/{}", self.config.log_dir, pcap_info.save_file_name);
        info!("Suricata Log Target Path: {}", current_log_dir);
        fs::create_dir_all(&current_log_dir)?;

        if pcap_info.packet_stats_dict.is_empty() {
            info!("No packets to process");
            return Ok(());
        }

        self.cmd_executor.process_pcap(
            &pcap_info.read_pcap_file_absolute_path,
            &current_log_dir,
        )?;

        if let Some(manager) = &self.process_manager {
            manager.wait_pcap_complete(&pcap_info.read_pcap_file_absolute_path)?;
        }

        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if let Some(manager) = &mut self.process_manager {
            manager.stop()?;
        }
        Ok(())
    }
}
