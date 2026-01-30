use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use log::{info, error};

#[derive(Debug)]
pub struct BlacklistManager {
    // 파일명(String) -> IP 목록(HashSet<String>)
    blacklists: HashMap<String, HashSet<String>>,
}

impl BlacklistManager {
    pub fn new() -> Self {
        Self {
            blacklists: HashMap::new(),
        }
    }

    pub fn load_from_dir<P: AsRef<Path>>(&mut self, dir_path: P) -> Result<()> {
        let dir_path = dir_path.as_ref();
        if !dir_path.exists() {
            return Err(anyhow::anyhow!("Blacklist directory does not exist: {:?}", dir_path));
        }

        info!("Loading blacklists from: {:?}", dir_path);

        for entry in WalkDir::new(dir_path).min_depth(1).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let path = entry.path();
                let file_name = path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();

                match self.load_file(path) {
                    Ok(ips) => {
                        info!("Loaded {} IPs from {}", ips.len(), file_name);
                        self.blacklists.insert(file_name, ips);
                    }
                    Err(e) => {
                        error!("Failed to load blacklist file {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(())
    }

    fn load_file(&self, path: &Path) -> Result<HashSet<String>> {
        let file = File::open(path).with_context(|| format!("Failed to open file: {:?}", path))?;
        let reader = BufReader::new(file);
        let mut ips = HashSet::new();

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // 간단한 유효성 검사 (IP 주소 형태인지)
            // 더 엄격한 검사가 필요하면 ipnetwork crate 사용 가능
            if line.parse::<std::net::IpAddr>().is_ok() {
                ips.insert(line.to_string());
            } else {
                // CIDR 지원 등은 여기서 확장 가능
                // 현재는 단순 IP만 저장
                // error!("Invalid IP format ignored: {}", line);
            }
        }

        Ok(ips)
    }

    pub fn is_blacklisted(&self, ip: &str) -> bool {
        for ips in self.blacklists.values() {
            if ips.contains(ip) {
                return true;
            }
        }
        false
    }
    
    pub fn get_blacklists(&self) -> &HashMap<String, HashSet<String>> {
        &self.blacklists
    }
}
